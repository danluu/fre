//! Whole-operation reduction for `LITERAL? BYTE_CLASS+ LITERAL?`, with at
//! least one nonempty literal, and the separately guarded ASCII-word form
//! `\b\w+SUFFIX\b`.
//!
//! Admission proves that the byte immediately before and after the class run
//! is outside the class. Construction selects the longer fixed literal as a
//! native `memmem` anchor. Anchor occurrences are visited monotonically,
//! including overlaps; only their adjacent maximal class run and opposite
//! literal are checked. Prefix-anchor order is match-start order. A suffix
//! anchor normally starts at a non-class barrier, so increasing suffix order
//! is also increasing maximal-run start order. The one-sided `CLASS+ SUFFIX`
//! form additionally admits a suffix wholly contained in the class: its first
//! occurrence identifies a disjoint maximal run, and the last overlapping
//! occurrence in that run determines the greedy end. Filtering starts behind
//! the preceding selected end therefore preserves greedy, leftmost-first,
//! non-overlapping Rust byte semantics without classifying unrelated bytes.
//! When an empty-prefix suffix begins outside the class but ends inside it,
//! backward recovery is clamped at that selected end so a consumed suffix tail
//! cannot hide the next legal repetition.
//!
//! For haystack width `N`, anchor width `A`, at most
//! `Q = max(0, N-A+1)` overlapping anchor starts exist. Restarting one byte
//! after a rejection makes finder service at most `N + Q*(A-1)`. Adjacent
//! class probes plus all disjoint maximal runs cost at most `N+Q` logical
//! classifications. On hosts with OS-usable SVE, plans built with a
//! caller-captured SIMD context retain one compiled directional ASCII run
//! scanner. Its construction-selected leaf returns both the maximal member-run
//! length and the exact number of bytes physically classified. A predicate
//! leaf can inspect at most 15 extra lanes in its terminating load. A
//! fixed-width leaf probes that block and rescans only through the failure, for
//! a combined overhead of exactly 16 classifications beyond the logical run on
//! that path. Other hosts retain the established fixed-width classifier and
//! scalar proof prefix. Only the opposite literal is compared for at most
//! `ceil(N/2)` run events.
//! These bounds, every finder call/candidate, results, persistent owner bytes,
//! and zero operation scratch are admitted before source access and checked
//! against cumulative actual counters after execution.
//!
//! The guarded mode is deliberately separate. For nonempty suffix width `A`,
//! it visits overlapping suffix occurrences with the same finder and uses
//! `Q = max(0, N-A+1)`. Finder calls are at most `Q` and finder service at
//! most `N + Q*(A-1)`. Count classifies at most the next and previous byte per
//! occurrence (`2Q`) and never calls a run scanner. Span sum classifies at
//! most `N+Q` logical bytes across right probes and disjoint backward
//! recoveries; retained SIMD scanners additionally publish their bounded
//! physical terminating-load overhead. Only span sum invokes backward run
//! recovery. Matches are at most `N/(A+1)`, and their disjoint span sum is at
//! most `N`.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all arithmetic affecting resources or indices is checked; bitmap shifts use proved 0..=63 operands"
)]

use core::{fmt, mem::size_of};

use fre_exact_alloc::CopyError;
use fre_simd_kernels::{
    ASCII_WIDE_BYTES, AsciiByteSet, AsciiByteSetClassifier, AsciiByteSetRunScanner,
    DispatchPolicy, Feature, SimdDispatchContext, VectorKind,
};
use memchr::memmem::{Finder, FinderBuilder};

use crate::unicode_scalar_aggregate::{decode_scalar, decode_scalar_with};
use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError, Window};

pub const PLAN_ID: &str = "literal-class-run-literal.maximal-byte-run.v4";
pub const COUNT_OPERATION_ID: &str = "literal-class-run-literal.count.unicode-off.v4";
pub const SPAN_SUM_OPERATION_ID: &str = "literal-class-run-literal.span-sum.unicode-off.v4";
/// Stable identity of allocation-free complete-span visitation.
pub const SPAN_VISIT_OPERATION_ID: &str =
    "literal-class-run-literal.span-visit.unicode-off.v1";
pub const SEARCH_OPERATION_ID: &str = "literal-class-run-literal.search.unicode-off.v2";
pub const SHORTEST_SEARCH_OPERATION_ID: &str =
    "literal-class-run-literal.shortest-search.unicode-off.v2";
pub const GENERAL_SEARCH_PLAN_ID: &str = "literal-class-run-search.generalized.unicode-off.v1";
pub const GENERAL_SEARCH_OPERATION_ID: &str =
    "literal-class-run-search.generalized.search.unicode-off.v1";
pub const GENERAL_SHORTEST_SEARCH_OPERATION_ID: &str =
    "literal-class-run-search.generalized.shortest-search.unicode-off.v1";
pub const BOUNDED_SEARCH_PLAN_ID: &str =
    "literal-class-run-search.finite-two-barrier.unicode-off.v1";
pub const BOUNDED_EXISTS_SEARCH_OPERATION_ID: &str =
    "literal-class-run-search.finite-two-barrier.exists.unicode-off.v1";
pub const BOUNDED_SEARCH_OPERATION_ID: &str =
    "literal-class-run-search.finite-two-barrier.search.unicode-off.v1";
pub const BOUNDED_SHORTEST_SEARCH_OPERATION_ID: &str =
    "literal-class-run-search.finite-two-barrier.shortest-search.unicode-off.v1";
pub(crate) const UNICODE_ALL_NON_ASCII_SEARCH_PLAN_ID: &str =
    "literal-class-run-search.unicode-all-non-ascii.v1";
pub(crate) const UNICODE_ALL_NON_ASCII_SEARCH_OPERATION_ID: &str =
    "literal-class-run-search.unicode-all-non-ascii.search.v1";
pub(crate) const UNICODE_ALL_NON_ASCII_SHORTEST_SEARCH_OPERATION_ID: &str =
    "literal-class-run-search.unicode-all-non-ascii.shortest-search.v1";

const FIXED_BUILD_WORK: usize = 32;
const LITERAL_BUILD_WORK_PER_BYTE: usize = 4;
const FINDER_BUILD_WORK_PER_BYTE: usize = 4;
const ANCHOR_SELECTION_WORK: usize = 2;
const BOUNDED_NATIVE_ADMISSION_WORK: usize = 1;
const BOUNDED_FINDER_BUILD_WORK_PER_BYTE: usize = 16;
const BOUNDED_FINDER_BUILD_FIXED_WORK: usize = 64;
const RANGE_BUILD_WORK: usize = 8;
const RANGE_WORD_WORK: usize = 4;
const FIXED_REDUCE_WORK: usize = 16;
const FINDER_SCAN_WORK: usize = 1;
const FINDER_CALL_WORK: usize = 4;
const ANCHOR_CANDIDATE_WORK: usize = 4;
const CLASSIFICATION_WORK: usize = 2;
const LITERAL_COMPARISON_WORK: usize = 2;
const RUN_WORK: usize = 12;
const MATCH_WORK: usize = 8;
// Building either reusable byte-set lookup charges its 128 nibble-column
// membership probes. The fixed classifier additionally binds and exposes
// narrow and wide leaves; the run scanner does the same for one paired
// direction profile. Static receipts are reconstructed without handle storage.
// These abstract charges stay independent of the dispatcher's variant count.
const SIMD_FIXED_CLASSIFIER_BUILD_WORK: usize = 128 + 2 + 2;
const SIMD_RUN_SCANNER_BUILD_WORK: usize = 128 + 1 + 1;
const SIMD_SCALAR_PROOF_BYTES: usize = ASCII_WIDE_BYTES;
const UNICODE_RANGE_PROOF_WORK: usize = 4;
const ASCII_WORD_CLASS_WORDS: [u64; 4] = [0x03ff_0000_0000_0000, 0x07ff_fffe_87ff_fffe, 0, 0];

/// Boundary interpretation proved by the builder and retained by the plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundarySemantics {
    /// An unguarded one- or two-sided literal/class-run contract.
    Unguarded,
    /// A complete ASCII word run ending in a nonempty all-word suffix.
    CompleteAsciiWordRun,
}

/// Minimum number of bytes consumed by the generalized repeated byte class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchRunMinimum {
    /// Greedy `CLASS*`; a surrounding literal keeps every match nonempty.
    Zero,
    /// Greedy `CLASS+`.
    One,
}

/// Stable identity of the compiled class-scan implementation in one plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClassScanIdentity {
    /// Fixed-width classifier retained on hosts without usable SVE.
    Fixed {
        narrow_variant_id: &'static str,
        wide_variant_id: &'static str,
        wide_delegate_variant_id: Option<&'static str>,
    },
    /// Directional maximal-run scanner used on SVE-capable hosts.
    Run { variant_id: &'static str },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClassScanKind {
    Scalar,
    Fixed,
    Run { max_classification_overhead: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Count,
    SpanSum,
    SpanVisit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SearchProjection {
    Selected,
    EarliestEnd,
}

#[derive(Clone, Copy, Debug)]
enum AsciiClassScanner {
    Fixed(AsciiByteSetClassifier),
    Run(AsciiByteSetRunScanner),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub prefix_bytes: usize,
    pub suffix_bytes: usize,
    pub class_words: [u64; 4],
    pub class_scan: Option<ClassScanIdentity>,
    pub boundary_semantics: BoundarySemantics,
    pub unicode: bool,
    pub greedy: bool,
    pub non_overlapping: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_literal_bytes: usize,
    pub max_class_ranges: usize,
    pub max_class_members: usize,
    pub max_build_work: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl BuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_literal_bytes: usize::MAX,
            max_class_ranges: usize::MAX,
            max_class_members: usize::MAX,
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
            max_literal_bytes: 4 * 1024 * 1024,
            max_class_ranges: 256,
            max_class_members: 256,
            max_build_work: 32 * 1024 * 1024,
            max_scratch_bytes: 0,
            max_persistent_bytes: 32 * 1024 * 1024,
            max_peak_bytes: 32 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub prefix_bytes: usize,
    pub suffix_bytes: usize,
    pub literal_bytes: usize,
    /// Canonical input ranges consumed by the builder. For the implicit-high
    /// Unicode representation, this is the original Unicode range count.
    pub class_ranges: usize,
    /// Members materialized in the retained byte bitmap. For the implicit-high
    /// Unicode representation, non-ASCII scalar membership is represented by
    /// the plan tag and this field therefore counts only ASCII members.
    pub class_members: usize,
    pub work_upper_bound: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_input_bytes: usize,
    pub max_source_reads: usize,
    pub max_work: usize,
    pub max_run_events: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl ReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_input_bytes: usize::MAX,
            max_source_reads: usize::MAX,
            max_work: usize::MAX,
            max_run_events: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 512 * 1024 * 1024,
            max_source_reads: 16 * 1024 * 1024 * 1024,
            max_work: 32 * 1024 * 1024 * 1024,
            max_run_events: 256 * 1024 * 1024,
            max_match_events: 64 * 1024 * 1024,
            max_count: 64 * 1024 * 1024,
            max_span_sum: u64::MAX,
            max_scratch_bytes: 0,
            max_persistent_bytes: 32 * 1024 * 1024,
            max_peak_bytes: 32 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub input_bytes: usize,
    pub source_reads: usize,
    pub finder_scanned_bytes: usize,
    pub finder_calls: usize,
    pub anchor_candidates: usize,
    pub classifications: usize,
    pub literal_comparisons: usize,
    pub work: usize,
    pub run_events: usize,
    pub candidate_events: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub source_reads: usize,
    pub finder_scanned_bytes: usize,
    pub finder_calls: usize,
    pub anchor_candidates: usize,
    pub classifications: usize,
    pub literal_comparisons: usize,
    pub runs: usize,
    pub candidates: usize,
    pub matches: usize,
    pub count: u64,
    pub span_sum: u64,
    pub work: usize,
    pub scratch_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    pub identity: OperationIdentity,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

/// Limits enforced against exact search work and anchor candidates.
///
/// A source-independent envelope still selects the ordinary SIMD path when
/// it fits. Larger windows use bounded scalar recovery and stop immediately
/// before the next charge would exceed either limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchLimits {
    pub max_work_upper_bound: u64,
    pub max_candidate_visits: usize,
    pub max_scratch_bytes: usize,
}

impl SearchLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work_upper_bound: u64::MAX,
            max_candidate_visits: usize::MAX,
            max_scratch_bytes: usize::MAX,
        }
    }
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            max_work_upper_bound: 32 * 1024 * 1024 * 1024,
            max_candidate_visits: 256 * 1024 * 1024,
            max_scratch_bytes: 0,
        }
    }
}

/// Source-independent search envelope and the exact counters charged before
/// the first selected match (or exhaustion).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchAccounting {
    pub operation_id: &'static str,
    pub window_bytes: usize,
    /// Original-haystack assertion bytes that may be inspected outside the
    /// requested window. This is zero for unguarded plans and at most two for
    /// the complete ASCII-word form.
    pub assertion_context_bytes: usize,
    pub candidate_visits_upper_bound: usize,
    pub source_reads_upper_bound: usize,
    pub work_upper_bound: u64,
    pub scratch_bytes: usize,
    pub candidate_visits: usize,
    pub finder_calls: usize,
    pub classifications: usize,
    pub literal_comparisons: usize,
    pub source_reads: usize,
    pub work: usize,
}

/// A checked source-derived search failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchError {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    CandidateLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        needed: u64,
        limit: u64,
    },
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    Kernel(ReduceError),
}

impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                f,
                "literal/class-run search window {start}..{end} is invalid for {haystack_len} bytes"
            ),
            Self::CandidateLimit { needed, limit } => {
                write!(
                    f,
                    "search needs candidate visit {needed}, exceeding {limit}"
                )
            }
            Self::WorkLimit { needed, limit } => {
                write!(f, "search needs work unit {needed}, exceeding {limit}")
            }
            Self::ScratchLimit { needed, limit } => {
                write!(f, "search needs {needed} scratch bytes, exceeding {limit}")
            }
            Self::Kernel(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for SearchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Kernel(error) => Some(error),
            Self::InvalidWindow { .. }
            | Self::CandidateLimit { .. }
            | Self::WorkLimit { .. }
            | Self::ScratchLimit { .. } => None,
        }
    }
}

impl From<ReduceError> for SearchError {
    fn from(value: ReduceError) -> Self {
        Self::Kernel(value)
    }
}

#[derive(Clone, Copy, Debug)]
struct SearchMeter {
    limits: SearchLimits,
    work_envelope_admitted: bool,
}

impl SearchMeter {
    fn new(upper: ReduceUpperBounds, limits: SearchLimits) -> Result<Self, SearchError> {
        let fixed =
            u64::try_from(FIXED_REDUCE_WORK).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "fixed search work as u64",
            })?;
        if fixed > limits.max_work_upper_bound {
            return Err(SearchError::WorkLimit {
                needed: fixed,
                limit: limits.max_work_upper_bound,
            });
        }
        let upper_work =
            u64::try_from(upper.work).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "search work upper bound as u64",
            })?;
        Ok(Self {
            limits,
            work_envelope_admitted: upper_work <= limits.max_work_upper_bound,
        })
    }

    fn ensure_work(
        self,
        actual: &ReduceActualCounters,
        requested: usize,
    ) -> Result<(), SearchError> {
        let consumed = u64::try_from(actual.work).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "actual search work as u64",
        })?;
        let requested = u64::try_from(requested).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "requested search work as u64",
        })?;
        let needed = consumed
            .checked_add(requested)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "metered search work",
            })?;
        if needed > self.limits.max_work_upper_bound {
            return Err(SearchError::WorkLimit {
                needed,
                limit: self.limits.max_work_upper_bound,
            });
        }
        Ok(())
    }

    fn remaining_work(self, actual: &ReduceActualCounters) -> Result<u64, SearchError> {
        let consumed = u64::try_from(actual.work).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "actual search work as u64",
        })?;
        Ok(self.limits.max_work_upper_bound.saturating_sub(consumed))
    }

    fn service_capacity(
        self,
        actual: &ReduceActualCounters,
        work_per_unit: usize,
    ) -> Result<usize, SearchError> {
        let work_per_unit =
            u64::try_from(work_per_unit).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "search service work unit as u64",
            })?;
        debug_assert_ne!(work_per_unit, 0);
        let capacity = self.remaining_work(actual)? / work_per_unit;
        Ok(usize::try_from(capacity).unwrap_or(usize::MAX))
    }

    fn ensure_anchor_candidate(self, actual: &ReduceActualCounters) -> Result<(), SearchError> {
        let needed =
            actual
                .anchor_candidates
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "metered search anchor candidates",
                })?;
        if needed > self.limits.max_candidate_visits {
            return Err(SearchError::CandidateLimit {
                needed,
                limit: self.limits.max_candidate_visits,
            });
        }
        Ok(())
    }
}

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

/// One complete non-overlapping match emitted by the reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteSpan {
    pub start: usize,
    pub end: usize,
}

/// Summary of one allocation-free complete-span traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanVisitResult {
    pub matches: usize,
    pub span_sum: u64,
    pub accounting: ReduceAccounting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    MissingLiteralAnchor,
    EmptyPrefix,
    NonEmptyPrefixForCompleteAsciiWordRun,
    EmptySuffix,
    EmptyClass,
    NonCanonicalClass,
    UnsupportedUnicodeClass,
    NonAsciiUnicodeLiteral,
    PrefixBoundaryInClass,
    SuffixBoundaryInClass,
    InexactAsciiWordClass,
    SuffixByteOutsideAsciiWordClass,
    UnsupportedSearchMinimum,
    ClassOutsideAsciiWord,
    SuffixByteOutsideAsciiWord,
    LiteralBytesLimit {
        needed: usize,
        limit: usize,
    },
    ClassRangesLimit {
        needed: usize,
        limit: usize,
    },
    ClassMembersLimit {
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
    InvalidFiniteBounds {
        minimum: usize,
        maximum: usize,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "literal/class-run/literal build failed: {self:?}")
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    InputBytesLimit {
        needed: usize,
        limit: usize,
    },
    SourceReadsLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "literal/class-run/literal reduction failed: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

#[derive(Clone, Copy, Debug)]
struct ByteClass([u64; 4]);

impl ByteClass {
    const fn empty() -> Self {
        Self([0; 4])
    }

    fn insert_range(
        &mut self,
        start: u8,
        end: u8,
        work: &mut BuildWork<'_>,
    ) -> Result<(), BuildError> {
        self.insert_range_with(start, end, |units| work.charge(units))
    }

    fn insert_range_with<E>(
        &mut self,
        start: u8,
        end: u8,
        mut charge: impl FnMut(usize) -> Result<(), E>,
    ) -> Result<(), E> {
        let first = usize::from(start) >> 6;
        let last = usize::from(end) >> 6;
        for word in first..=last {
            charge(RANGE_WORD_WORK)?;
            let low = if word == first {
                u32::from(start) & 63
            } else {
                0
            };
            let high = if word == last {
                u32::from(end) & 63
            } else {
                63
            };
            self.0[word] |= u64::MAX << low & u64::MAX >> (63 - high);
        }
        Ok(())
    }

    fn contains(self, byte: u8) -> bool {
        let word = usize::from(byte) >> 6;
        let bit = u32::from(byte) & 63;
        self.0[word] & (1_u64 << bit) != 0
    }

    const fn is_ascii(self) -> bool {
        self.0[2] == 0 && self.0[3] == 0
    }

    const fn is_ascii_word_subset(self) -> bool {
        self.0[0] & !ASCII_WORD_CLASS_WORDS[0] == 0
            && self.0[1] & !ASCII_WORD_CLASS_WORDS[1] == 0
            && self.0[2] == 0
            && self.0[3] == 0
    }

    const fn ascii_set(self) -> AsciiByteSet {
        AsciiByteSet::from_words([self.0[0], self.0[1]])
    }
}

#[derive(Clone, Copy)]
struct PreparedClass {
    class: ByteClass,
    input_ranges: usize,
    materialized_members: usize,
    work: usize,
}

const fn is_ascii_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Anchor {
    Prefix,
    Suffix,
    CompleteAsciiWordSuffix,
}

/// Construction-resolved geometry for the direct literal/class-run owner.
///
/// `SuffixInsideClass` is semantically distinct from an ordinary suffix
/// anchor: greedy selection must inspect overlapping suffix occurrences from
/// the end of the class run. Keeping that proof in the retained plan avoids
/// rediscovering it at every operation boundary.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResolvedSearchGeometry {
    GeneralPrefix,
    GeneralSuffix,
    SuffixInsideClass,
    CompleteAsciiWordSuffix,
}

#[cfg(test)]
std::thread_local! {
    static TEST_SEARCH_PREFLIGHT_CALLS: core::cell::Cell<usize> = const {
        core::cell::Cell::new(0)
    };
}

#[cfg(test)]
fn reset_test_search_preflight_calls() {
    TEST_SEARCH_PREFLIGHT_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
fn test_search_preflight_calls() -> usize {
    TEST_SEARCH_PREFLIGHT_CALLS.with(core::cell::Cell::get)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundedNativeAdmission {
    Unconditional,
    RequireCostProof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundedAnchorScoreMode {
    LazyPreference,
    AdmissionProof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BoundedAnchorSelection {
    preferred: Anchor,
    strict_full_width_repetition: Option<Anchor>,
    strict_full_width_opposite_period: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BoundedRepetitionPreference {
    preferred: Anchor,
    opposite_primitive_period: usize,
}

#[derive(Debug)]
pub struct LiteralClassRunLiteralPlan {
    anchor: Finder<'static>,
    opposite_literal: Box<[u8]>,
    geometry: ResolvedSearchGeometry,
    class: ByteClass,
    ascii_scanner: Option<AsciiClassScanner>,
    build: BuildAccounting,
}

/// Search-only plan for canonical greedy byte-class runs whose semantics are
/// broader than the reduction plan's maximal-run partition invariant.
///
/// Unguarded plans retain a nonempty prefix anchor and may use `CLASS*` or a
/// prefix whose final byte belongs to the class. Guarded plans retain a
/// nonempty word suffix and admit any nonempty ASCII-word subset class.
#[derive(Debug)]
pub struct LiteralClassRunSearchPlan {
    anchor: Finder<'static>,
    opposite_literal: Box<[u8]>,
    anchor_kind: Anchor,
    class: ByteClass,
    ascii_scanner: Option<AsciiClassScanner>,
    minimum: SearchRunMinimum,
    unicode_all_non_ascii: bool,
    build: BuildAccounting,
}

/// Stateless direct search for one finite greedy class run between two exact
/// nonempty literal barriers.
///
/// The builder proves that the prefix's final byte and suffix's first byte
/// are outside the repeated class. Consequently a maximal forward run after
/// a prefix occurrence and a maximal backward run before a suffix occurrence
/// are the same unique repetition. The two outside-class guards also prove
/// that accepted spans cannot cross: increasing prefix starts imply increasing
/// suffix starts and conversely. The lower-frequency barrier can therefore
/// drive every projection, and its first accepted candidate is both the
/// selected match and the earliest end without replay or source-derived
/// retained state. Equal-frequency barriers retain the established bounded-
/// sample repetition preference: for literal width `n` and sampled primitive
/// period `p`, the smaller `n/p` factor wins. This is a routing heuristic when
/// either literal exceeds the sample; it becomes a strict native-admission
/// proof only when the sample covers both complete literals. Literal width
/// remains the final tie-breaker when the sampled factors are equal.
#[derive(Debug)]
pub struct BoundedLiteralClassRunPlan {
    prefix: Finder<'static>,
    suffix: Finder<'static>,
    class: ByteClass,
    ascii_scanner: Option<AsciiClassScanner>,
    minimum: usize,
    maximum: usize,
    preferred_anchor: Anchor,
    build: BuildAccounting,
}

impl LiteralClassRunLiteralPlan {
    pub fn build<I>(
        prefix: &[u8],
        ranges: I,
        suffix: &[u8],
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_attempt(prefix, ranges, suffix, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build a plan whose eligible ASCII class scan uses one immutable host
    /// capability snapshot captured before this accounted transaction.
    pub fn build_with_dispatch<I>(
        dispatch: SimdDispatchContext,
        prefix: &[u8],
        ranges: I,
        suffix: &[u8],
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_attempt_with_dispatch(dispatch, prefix, ranges, suffix, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build while retaining exact successful or partial terminal effects.
    #[allow(
        clippy::too_many_lines,
        reason = "construction keeps admission, exact allocation, finder publication, and the terminal receipt in one auditable transaction"
    )]
    pub fn build_attempt<I>(
        prefix: &[u8],
        ranges: I,
        suffix: &[u8],
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_attempt_inner(
            None,
            BoundarySemantics::Unguarded,
            prefix,
            ranges,
            suffix,
            limits,
        )
    }

    /// Build with a pre-captured dispatch context while retaining exact
    /// successful or partial terminal effects.
    pub fn build_attempt_with_dispatch<I>(
        dispatch: SimdDispatchContext,
        prefix: &[u8],
        ranges: I,
        suffix: &[u8],
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_attempt_inner(
            Some((dispatch, DispatchPolicy::Auto)),
            BoundarySemantics::Unguarded,
            prefix,
            ranges,
            suffix,
            limits,
        )
    }

    /// Build the guarded `\b ASCII_WORD+ SUFFIX \b` specialization.
    ///
    /// `prefix` must be empty, `ranges` must be exactly the complete ASCII
    /// word class, and every byte of the nonempty suffix must belong to that
    /// class. Keeping those proof inputs explicit lets this kernel revalidate
    /// the facade's HIR admission before publishing a guarded plan.
    pub fn build_complete_ascii_word_run<I>(
        prefix: &[u8],
        ranges: I,
        suffix: &[u8],
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_complete_ascii_word_run_attempt(prefix, ranges, suffix, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build the guarded specialization with a caller-captured SIMD context.
    pub fn build_complete_ascii_word_run_with_dispatch<I>(
        dispatch: SimdDispatchContext,
        prefix: &[u8],
        ranges: I,
        suffix: &[u8],
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_complete_ascii_word_run_attempt_with_dispatch(
            dispatch, prefix, ranges, suffix, limits,
        )
        .map(DirectBuildAttempt::into_plan)
        .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build the guarded specialization while retaining terminal effects.
    pub fn build_complete_ascii_word_run_attempt<I>(
        prefix: &[u8],
        ranges: I,
        suffix: &[u8],
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_attempt_inner(
            None,
            BoundarySemantics::CompleteAsciiWordRun,
            prefix,
            ranges,
            suffix,
            limits,
        )
    }

    /// Build the guarded specialization with captured dispatch while
    /// retaining exact successful or partial terminal effects.
    pub fn build_complete_ascii_word_run_attempt_with_dispatch<I>(
        dispatch: SimdDispatchContext,
        prefix: &[u8],
        ranges: I,
        suffix: &[u8],
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_attempt_inner(
            Some((dispatch, DispatchPolicy::Auto)),
            BoundarySemantics::CompleteAsciiWordRun,
            prefix,
            ranges,
            suffix,
            limits,
        )
    }

    #[cfg(test)]
    fn build_with_dispatch_policy<I>(
        dispatch: SimdDispatchContext,
        policy: DispatchPolicy,
        prefix: &[u8],
        ranges: I,
        suffix: &[u8],
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_attempt_inner(
            Some((dispatch, policy)),
            BoundarySemantics::Unguarded,
            prefix,
            ranges,
            suffix,
            limits,
        )
        .map(DirectBuildAttempt::into_plan)
        .map_err(DirectBuildAttemptError::into_source)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "construction keeps admission, exact allocation, optional classifier compilation, finder publication, and the terminal receipt in one auditable transaction"
    )]
    fn build_attempt_inner<I>(
        dispatch: Option<(SimdDispatchContext, DispatchPolicy)>,
        boundary_semantics: BoundarySemantics,
        prefix: &[u8],
        mut ranges: I,
        suffix: &[u8],
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        let mut actual = DirectBuildAttemptActual::default();
        let result = (|| {
            match boundary_semantics {
                BoundarySemantics::Unguarded if prefix.is_empty() && suffix.is_empty() => {
                    return Err(BuildError::MissingLiteralAnchor);
                }
                BoundarySemantics::CompleteAsciiWordRun if !prefix.is_empty() => {
                    return Err(BuildError::NonEmptyPrefixForCompleteAsciiWordRun);
                }
                BoundarySemantics::Unguarded | BoundarySemantics::CompleteAsciiWordRun => {}
            }
            if boundary_semantics == BoundarySemantics::CompleteAsciiWordRun && suffix.is_empty() {
                return Err(BuildError::EmptySuffix);
            }
            let literal_bytes =
                prefix
                    .len()
                    .checked_add(suffix.len())
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "literal byte total",
                    })?;
            let anchor_bytes = prefix.len().max(suffix.len());
            enforce_build(
                literal_bytes,
                limits.max_literal_bytes,
                BuildResource::LiteralBytes,
            )?;
            let scratch_bytes = 0;
            let persistent_bytes = size_of::<Self>().checked_add(literal_bytes).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "persistent bytes",
                },
            )?;
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

            let literal_work = literal_bytes
                .checked_mul(LITERAL_BUILD_WORK_PER_BYTE)
                .and_then(|value| {
                    anchor_bytes
                        .checked_mul(FINDER_BUILD_WORK_PER_BYTE)
                        .and_then(|finder| value.checked_add(finder))
                })
                .and_then(|value| value.checked_add(FIXED_BUILD_WORK))
                .and_then(|value| value.checked_add(ANCHOR_SELECTION_WORK))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "fixed, literal, and finder build work",
                })?;
            let mut work = BuildWork::new(limits.max_build_work, &mut actual);
            work.charge(literal_work)?;
            let (class, class_ranges, class_members) = build_class(&mut ranges, limits, &mut work)?;
            let geometry = match boundary_semantics {
                BoundarySemantics::Unguarded => {
                    work.charge(2)?;
                    if prefix
                        .last()
                        .is_some_and(|&boundary| class.contains(boundary))
                    {
                        return Err(BuildError::PrefixBoundaryInClass);
                    }
                    let suffix_is_inside_class = suffix
                        .first()
                        .is_some_and(|&boundary| class.contains(boundary));
                    if suffix_is_inside_class {
                        if !prefix.is_empty() {
                            return Err(BuildError::SuffixBoundaryInClass);
                        }
                        work.charge(suffix.len())?;
                        if !suffix.iter().all(|&byte| class.contains(byte)) {
                            return Err(BuildError::SuffixBoundaryInClass);
                        }
                    }
                    if suffix_is_inside_class {
                        ResolvedSearchGeometry::SuffixInsideClass
                    } else if prefix.len() >= suffix.len() {
                        ResolvedSearchGeometry::GeneralPrefix
                    } else {
                        ResolvedSearchGeometry::GeneralSuffix
                    }
                }
                BoundarySemantics::CompleteAsciiWordRun => {
                    work.charge(1)?;
                    if class.0 != ASCII_WORD_CLASS_WORDS {
                        return Err(BuildError::InexactAsciiWordClass);
                    }
                    for &byte in suffix {
                        work.charge(1)?;
                        if !class.contains(byte) {
                            return Err(BuildError::SuffixByteOutsideAsciiWordClass);
                        }
                    }
                    ResolvedSearchGeometry::CompleteAsciiWordSuffix
                }
            };
            let ascii_scanner = build_ascii_scanner(
                dispatch.filter(|_| class.is_ascii()),
                class,
                false,
                &mut work,
            )?;
            let work_upper_bound = work.used;

            let prefix = copy_literal(prefix, "prefix")?;
            if !prefix.is_empty() {
                record_literal_copy(&mut actual, prefix.len())?;
            }
            let suffix = copy_literal(suffix, "suffix")?;
            if !suffix.is_empty() {
                record_literal_copy(&mut actual, suffix.len())?;
            }
            let prefix_bytes = prefix.len();
            let suffix_bytes = suffix.len();
            let (anchor, opposite_literal) = match geometry {
                ResolvedSearchGeometry::GeneralPrefix => {
                    (FinderBuilder::new().build_forward_owned(prefix), suffix)
                }
                ResolvedSearchGeometry::GeneralSuffix
                | ResolvedSearchGeometry::SuffixInsideClass
                | ResolvedSearchGeometry::CompleteAsciiWordSuffix => {
                    (FinderBuilder::new().build_forward_owned(suffix), prefix)
                }
            };
            actual.initialized_bytes = actual
                .initialized_bytes
                .checked_add(size_of::<Self>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "plan initialized bytes",
                })?;
            actual.live_persistent_bytes = actual
                .live_persistent_bytes
                .checked_add(size_of::<Self>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "plan live persistent bytes",
                })?;
            actual.peak_bytes = actual.peak_bytes.max(actual.live_persistent_bytes);
            debug_assert_eq!(actual.live_persistent_bytes, persistent_bytes);
            Ok(Self {
                anchor,
                opposite_literal,
                geometry,
                class,
                ascii_scanner,
                build: BuildAccounting {
                    prefix_bytes,
                    suffix_bytes,
                    literal_bytes,
                    class_ranges,
                    class_members,
                    work_upper_bound,
                    scratch_bytes,
                    persistent_bytes,
                    peak_bytes,
                },
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
        self.identity(COUNT_OPERATION_ID)
    }

    #[must_use]
    pub const fn span_sum_identity(&self) -> OperationIdentity {
        self.identity(SPAN_SUM_OPERATION_ID)
    }

    #[must_use]
    pub const fn span_visit_identity(&self) -> OperationIdentity {
        self.identity(SPAN_VISIT_OPERATION_ID)
    }

    const fn identity(&self, operation_id: &'static str) -> OperationIdentity {
        OperationIdentity {
            plan_id: PLAN_ID,
            operation_id,
            prefix_bytes: self.build.prefix_bytes,
            suffix_bytes: self.build.suffix_bytes,
            class_words: self.class.0,
            class_scan: match self.ascii_scanner {
                Some(AsciiClassScanner::Fixed(classifier)) => {
                    let selection = classifier.selection();
                    let narrow = selection.narrow();
                    let wide = selection.wide();
                    Some(ClassScanIdentity::Fixed {
                        narrow_variant_id: narrow.variant_id,
                        wide_variant_id: wide.variant_id,
                        wide_delegate_variant_id: wide.delegate_variant_id,
                    })
                }
                Some(AsciiClassScanner::Run(scanner)) => {
                    let selection = scanner.selection();
                    Some(ClassScanIdentity::Run {
                        variant_id: selection.variant_id,
                    })
                }
                None => None,
            },
            boundary_semantics: self.boundary_semantics(),
            unicode: false,
            greedy: true,
            non_overlapping: true,
        }
    }

    fn prefix(&self) -> &[u8] {
        match self.geometry {
            ResolvedSearchGeometry::GeneralPrefix => self.anchor.needle(),
            ResolvedSearchGeometry::GeneralSuffix
            | ResolvedSearchGeometry::SuffixInsideClass
            | ResolvedSearchGeometry::CompleteAsciiWordSuffix => &self.opposite_literal,
        }
    }

    fn suffix(&self) -> &[u8] {
        match self.geometry {
            ResolvedSearchGeometry::GeneralPrefix => &self.opposite_literal,
            ResolvedSearchGeometry::GeneralSuffix
            | ResolvedSearchGeometry::SuffixInsideClass
            | ResolvedSearchGeometry::CompleteAsciiWordSuffix => self.anchor.needle(),
        }
    }

    #[must_use]
    pub const fn boundary_semantics(&self) -> BoundarySemantics {
        match self.geometry {
            ResolvedSearchGeometry::GeneralPrefix
            | ResolvedSearchGeometry::GeneralSuffix
            | ResolvedSearchGeometry::SuffixInsideClass => BoundarySemantics::Unguarded,
            ResolvedSearchGeometry::CompleteAsciiWordSuffix => {
                BoundarySemantics::CompleteAsciiWordRun
            }
        }
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        let upper = self.preflight(haystack.len(), Operation::Count, limits)?;
        let actual = self.scan(haystack, Operation::Count, upper)?;
        Ok(CountResult {
            count: actual.count,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
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
        let upper = self.preflight(haystack.len(), Operation::SpanSum, limits)?;
        let actual = self.scan(haystack, Operation::SpanSum, upper)?;
        Ok(SpanSumResult {
            span_sum: actual.span_sum,
            accounting: ReduceAccounting {
                identity: self.span_sum_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }

    /// Visit every complete non-overlapping match in one allocation-free
    /// traversal. Prospective limits are checked before source access or the
    /// first callback.
    pub fn visit_spans<F>(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
        mut visitor: F,
    ) -> Result<SpanVisitResult, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        let upper = self.preflight(haystack.len(), Operation::SpanVisit, limits)?;
        let actual =
            self.scan_with_visitor(haystack, Operation::SpanVisit, upper, &mut visitor)?;
        Ok(SpanVisitResult {
            matches: actual.matches,
            span_sum: actual.span_sum,
            accounting: ReduceAccounting {
                identity: self.span_visit_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }

    /// Find the selected leftmost-first span in the full haystack.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.find_window(haystack, Window::full(haystack), limits)
    }

    /// Find the selected leftmost-first span wholly inside `window`.
    ///
    /// The guarded ASCII-word form evaluates both word assertions against the
    /// original haystack. Unguarded repetitions are deliberately clamped to
    /// the requested window, matching Rust's `find_at`/ranged-search contract.
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.search_window(haystack, window, limits, SearchProjection::Selected)
    }

    /// Return the first accepting end offset in the full haystack.
    pub fn shortest(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.shortest_window(haystack, Window::full(haystack), limits)
    }

    /// Return the first accepting end offset wholly inside `window`.
    ///
    /// This differs from selected greedy search for prefix-only forms and for
    /// the one-sided form whose suffix is wholly inside the repeated class.
    pub fn shortest_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        let (matched, accounting) =
            self.search_window(haystack, window, limits, SearchProjection::EarliestEnd)?;
        Ok((matched.map(|(_, end)| end), accounting))
    }

    /// Whether any selected match exists without retaining diagnostic
    /// accounting for the admitted unguarded full-envelope route.
    #[inline]
    pub fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        if !matches!(
            self.geometry,
            ResolvedSearchGeometry::GeneralPrefix | ResolvedSearchGeometry::GeneralSuffix
        ) || limits != SearchLimits::unlimited()
        {
            return self.is_match_window_incumbent(haystack, window, limits);
        }
        let (upper, _, _, meter) = self.search_preflight(haystack.len(), window, limits)?;
        if !meter.work_envelope_admitted || upper.anchor_candidates > limits.max_candidate_visits {
            return self.is_match_window_incumbent(haystack, window, limits);
        }
        let slice = &haystack[window.start()..window.end()];
        Ok(self.search_general_exists_value(slice))
    }

    /// Whether the ordinary immutable full-haystack operation has a match.
    ///
    /// Construction resolves the only static specialist decision. General
    /// prefix/suffix, contained-suffix, and complete ASCII-word geometry enter
    /// report-free existence loops directly. Ranged, finite, accounted, and
    /// session APIs deliberately continue to use
    /// [`Self::is_match_window_value`].
    #[doc(hidden)]
    #[inline]
    pub fn is_match_full_ordinary_value(&self, haystack: &[u8]) -> Result<bool, SearchError> {
        match self.geometry {
            ResolvedSearchGeometry::GeneralPrefix | ResolvedSearchGeometry::GeneralSuffix => {
                Ok(self.search_general_exists_value(haystack))
            }
            ResolvedSearchGeometry::SuffixInsideClass => {
                Ok(self.search_suffix_inside_class_exists_value(haystack))
            }
            ResolvedSearchGeometry::CompleteAsciiWordSuffix => {
                Ok(self.search_complete_ascii_word_run_value(haystack).is_some())
            }
        }
    }

    /// Return the selected ordinary full-haystack span without retaining
    /// diagnostic accounting for general prefix/suffix, contained-suffix, and
    /// complete ASCII-word geometry. Ranged, finite, accounted, session,
    /// iterator, and reusable value APIs continue to use [`Self::find_window`].
    #[doc(hidden)]
    #[inline]
    pub fn find_full_ordinary_value(
        &self,
        haystack: &[u8],
    ) -> Result<Option<(usize, usize)>, SearchError> {
        match self.geometry {
            ResolvedSearchGeometry::GeneralPrefix | ResolvedSearchGeometry::GeneralSuffix => {
                Ok(self.search_general_selected_value(haystack))
            }
            ResolvedSearchGeometry::SuffixInsideClass => {
                Ok(self.search_suffix_inside_class_selected_value(haystack))
            }
            ResolvedSearchGeometry::CompleteAsciiWordSuffix => {
                Ok(self.search_complete_ascii_word_run_value(haystack))
            }
        }
    }

    #[inline]
    fn is_match_window_incumbent(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.shortest_window(haystack, window, limits)
            .map(|(matched, _)| matched.is_some())
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the admitted value route keeps every anchor and run offset within its validated slice"
    )]
    fn search_general_exists_value(&self, haystack: &[u8]) -> bool {
        let mut cursor = 0_usize;
        loop {
            let Some(relative) = self.anchor.find(&haystack[cursor..]) else {
                return false;
            };
            let anchor_start = cursor + relative;
            match self.geometry {
                ResolvedSearchGeometry::GeneralPrefix => {
                    let anchor_end = anchor_start + self.prefix().len();
                    if let Some(run_end) = scan_class_run_forward_value(
                        haystack,
                        self.class,
                        self.ascii_scanner.as_ref(),
                        anchor_end,
                    ) {
                        if haystack
                            .get(run_end..)
                            .is_some_and(|remaining| remaining.starts_with(self.suffix()))
                        {
                            return true;
                        }
                    }
                }
                ResolvedSearchGeometry::GeneralSuffix => {
                    if let Some(run_start) = scan_class_run_backward_value(
                        haystack,
                        self.class,
                        self.ascii_scanner.as_ref(),
                        anchor_start,
                    ) {
                        if let Some(prefix_start) = run_start.checked_sub(self.prefix().len()) {
                            if haystack
                                .get(prefix_start..run_start)
                                .is_some_and(|actual| actual == self.prefix())
                            {
                                return true;
                            }
                        }
                    }
                }
                ResolvedSearchGeometry::SuffixInsideClass
                | ResolvedSearchGeometry::CompleteAsciiWordSuffix => {
                    debug_assert!(false, "non-general geometry must use incumbent search");
                    return false;
                }
            }
            cursor = anchor_start + 1;
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the admitted value route keeps every anchor and run offset within its full-haystack slice"
    )]
    fn search_general_selected_value(&self, haystack: &[u8]) -> Option<(usize, usize)> {
        let mut cursor = 0_usize;
        loop {
            let relative = self.anchor.find(&haystack[cursor..])?;
            let anchor_start = cursor + relative;
            let anchor_end = anchor_start + self.anchor.needle().len();
            let matched = match self.geometry {
                ResolvedSearchGeometry::GeneralPrefix => {
                    scan_class_run_forward_value(
                        haystack,
                        self.class,
                        self.ascii_scanner.as_ref(),
                        anchor_end,
                    )
                    .filter(|&run_end| {
                        haystack
                            .get(run_end..)
                            .is_some_and(|remaining| remaining.starts_with(self.suffix()))
                    })
                    .map(|run_end| (anchor_start, run_end + self.suffix().len()))
                }
                ResolvedSearchGeometry::GeneralSuffix => {
                    scan_class_run_backward_value(
                        haystack,
                        self.class,
                        self.ascii_scanner.as_ref(),
                        anchor_start,
                    )
                    .and_then(|run_start| {
                        if self.prefix().is_empty() {
                            Some(run_start)
                        } else {
                            run_start.checked_sub(self.prefix().len())
                        }
                    })
                    .filter(|&start| {
                        haystack
                            .get(start..anchor_start)
                            .is_some_and(|actual| actual.starts_with(self.prefix()))
                    })
                    .map(|start| (start, anchor_end))
                }
                ResolvedSearchGeometry::SuffixInsideClass
                | ResolvedSearchGeometry::CompleteAsciiWordSuffix => {
                    debug_assert!(false, "non-general geometry must use incumbent search");
                    return None;
                }
            };
            if matched.is_some() {
                return matched;
            }
            cursor = anchor_start + 1;
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the nonempty suffix finder bounds every offset within the full haystack"
    )]
    fn search_complete_ascii_word_run_value(
        &self,
        haystack: &[u8],
    ) -> Option<(usize, usize)> {
        debug_assert_eq!(
            self.geometry,
            ResolvedSearchGeometry::CompleteAsciiWordSuffix
        );
        let mut cursor = 0_usize;
        loop {
            let relative = self.anchor.find(&haystack[cursor..])?;
            let suffix_start = cursor + relative;
            let suffix_end = suffix_start + self.anchor.needle().len();
            if haystack
                .get(suffix_end)
                .is_some_and(|&byte| self.class.contains(byte))
            {
                cursor = suffix_start + 1;
                continue;
            }
            if let Some(run_start) = scan_class_run_backward_value(
                haystack,
                self.class,
                self.ascii_scanner.as_ref(),
                suffix_start,
            )
            .filter(|&start| start < suffix_start)
            {
                return Some((run_start, suffix_end));
            }
            cursor = suffix_start + 1;
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "each finder result is bounded by the full haystack and every rejected overlap advances one byte"
    )]
    fn search_suffix_inside_class_exists_value(&self, haystack: &[u8]) -> bool {
        debug_assert_eq!(self.geometry, ResolvedSearchGeometry::SuffixInsideClass);
        debug_assert!(self.prefix().is_empty());
        // Construction proved every suffix byte belongs to the class. A
        // suffix occurrence is therefore a complete match exactly when its
        // immediate predecessor exists and belongs to the same class run.
        let mut cursor = 0_usize;
        loop {
            let Some(relative) = self.anchor.find(&haystack[cursor..]) else {
                return false;
            };
            let suffix_start = cursor + relative;
            if suffix_start > 0 && self.class.contains(haystack[suffix_start - 1]) {
                return true;
            }
            cursor = suffix_start + 1;
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "slice-proved suffix and run boundaries bound every overlap restart and selected end"
    )]
    fn search_suffix_inside_class_selected_value(
        &self,
        haystack: &[u8],
    ) -> Option<(usize, usize)> {
        debug_assert_eq!(self.geometry, ResolvedSearchGeometry::SuffixInsideClass);
        debug_assert!(self.prefix().is_empty());
        let suffix_bytes = self.anchor.needle().len();
        debug_assert!(suffix_bytes != 0);
        let mut cursor = 0_usize;
        loop {
            // The earliest suffix globally identifies the earliest maximal
            // class run that can contain a match. Greedy class repetition
            // then selects the last overlapping suffix in that run.
            let relative = self.anchor.find(&haystack[cursor..])?;
            let first_suffix = cursor + relative;
            let first_suffix_end = first_suffix + suffix_bytes;
            let run_start = scan_class_run_backward_value(
                haystack,
                self.class,
                self.ascii_scanner.as_ref(),
                first_suffix,
            )
            .unwrap_or(first_suffix);
            let run_end = scan_class_run_forward_value(
                haystack,
                self.class,
                self.ascii_scanner.as_ref(),
                first_suffix_end,
            )
            .unwrap_or(first_suffix_end);

            let mut chosen = (run_start < first_suffix).then_some(first_suffix);
            let mut overlap_cursor = first_suffix + 1;
            while run_end.saturating_sub(overlap_cursor) >= suffix_bytes {
                let Some(relative) = self.anchor.find(&haystack[overlap_cursor..run_end]) else {
                    break;
                };
                let next_suffix = overlap_cursor + relative;
                chosen = Some(next_suffix);
                overlap_cursor = next_suffix + 1;
            }
            if let Some(suffix_start) = chosen {
                return Some((run_start, suffix_start + suffix_bytes));
            }
            // With every suffix byte in the class, no occurrence can cross
            // the non-class byte that terminated this invalid run.
            cursor = run_end;
        }
    }

    fn search_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
        projection: SearchProjection,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        let (upper, window_bytes, assertion_context_bytes, meter) =
            self.search_preflight(haystack.len(), window, limits)?;
        let slice =
            haystack
                .get(window.start()..window.end())
                .ok_or(SearchError::InvalidWindow {
                    start: window.start(),
                    end: window.end(),
                    haystack_len: haystack.len(),
                })?;
        let (matched, actual) = match self.geometry {
            ResolvedSearchGeometry::CompleteAsciiWordSuffix => {
                self.search_complete_ascii_word_run(haystack, slice, window.start(), upper, meter)?
            }
            ResolvedSearchGeometry::SuffixInsideClass => {
                self.search_suffix_inside_class(slice, projection, upper, meter)?
            }
            ResolvedSearchGeometry::GeneralPrefix | ResolvedSearchGeometry::GeneralSuffix => {
                self.search_general(slice, projection, upper, meter)?
            }
        };
        let matched =
            matched
                .map(|(start, end)| {
                    let start = window.start().checked_add(start).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "absolute search match start",
                        },
                    )?;
                    let end =
                        window
                            .start()
                            .checked_add(end)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "absolute search match end",
                            })?;
                    Ok::<(usize, usize), ReduceError>((start, end))
                })
                .transpose()?;
        let operation_id = match projection {
            SearchProjection::Selected => SEARCH_OPERATION_ID,
            SearchProjection::EarliestEnd => SHORTEST_SEARCH_OPERATION_ID,
        };
        Ok((
            matched,
            SearchAccounting {
                operation_id,
                window_bytes,
                assertion_context_bytes,
                candidate_visits_upper_bound: upper.anchor_candidates,
                source_reads_upper_bound: upper.source_reads,
                work_upper_bound: u64::try_from(upper.work).unwrap_or(u64::MAX),
                scratch_bytes: upper.scratch_bytes,
                candidate_visits: actual.anchor_candidates,
                finder_calls: actual.finder_calls,
                classifications: actual.classifications,
                literal_comparisons: actual.literal_comparisons,
                source_reads: actual.source_reads,
                work: actual.work,
            },
        ))
    }

    fn search_preflight(
        &self,
        haystack_len: usize,
        window: Window,
        limits: SearchLimits,
    ) -> Result<(ReduceUpperBounds, usize, usize, SearchMeter), SearchError> {
        #[cfg(test)]
        TEST_SEARCH_PREFLIGHT_CALLS.with(|calls| calls.set(calls.get() + 1));
        if window.start() > window.end() || window.end() > haystack_len {
            return Err(SearchError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len,
            });
        }
        let window_bytes =
            window
                .end()
                .checked_sub(window.start())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "search window bytes",
                })?;
        let assertion_context_bytes =
            if self.boundary_semantics() == BoundarySemantics::CompleteAsciiWordRun {
                usize::from(window.start() != 0) + usize::from(window.end() != haystack_len)
            } else {
                0
            };
        // The reduction proof already publishes a complete full-traversal
        // envelope. Search is a prefix of that traversal. Guarded ranged
        // search can additionally inspect one original byte at each edge, so
        // derive the envelope over the exact window-plus-context width.
        let accounted_bytes = window_bytes.checked_add(assertion_context_bytes).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "search window plus assertion context",
            },
        )?;
        let upper = self.reduce_upper_bounds(accounted_bytes, Operation::SpanSum)?;
        if upper.scratch_bytes > limits.max_scratch_bytes {
            return Err(SearchError::ScratchLimit {
                needed: upper.scratch_bytes,
                limit: limits.max_scratch_bytes,
            });
        }
        let meter = SearchMeter::new(upper, limits)?;
        Ok((upper, window_bytes, assertion_context_bytes, meter))
    }

    fn search_general(
        &self,
        haystack: &[u8],
        projection: SearchProjection,
        upper: ReduceUpperBounds,
        meter: SearchMeter,
    ) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
        let mut actual = new_search_actual();
        let mut cursor = 0_usize;
        loop {
            let Some((anchor_start, anchor_end)) =
                self.next_anchor(haystack, cursor, haystack.len(), &mut actual, meter)?
            else {
                return finish_search(None, actual, upper);
            };
            let candidate = match self.geometry {
                ResolvedSearchGeometry::GeneralPrefix
                    if projection == SearchProjection::EarliestEnd && self.suffix().is_empty() =>
                {
                    self.search_prefix_anchor_shortest_candidate(
                        haystack,
                        anchor_start,
                        anchor_end,
                        &mut actual,
                        meter,
                    )?
                }
                ResolvedSearchGeometry::GeneralPrefix => self.search_prefix_anchor_candidate(
                    haystack,
                    anchor_start,
                    anchor_end,
                    0,
                    &mut actual,
                    meter,
                )?,
                ResolvedSearchGeometry::GeneralSuffix => self.search_suffix_anchor_candidate(
                    haystack,
                    anchor_start,
                    anchor_end,
                    0,
                    &mut actual,
                    meter,
                )?,
                ResolvedSearchGeometry::SuffixInsideClass
                | ResolvedSearchGeometry::CompleteAsciiWordSuffix => {
                    debug_assert!(
                        false,
                        "guarded suffix route must retain original-haystack assertions"
                    );
                    return Err(SearchError::Kernel(ReduceError::AccountingInvariant {
                        resource: "guarded search dispatch",
                        actual: 1,
                        upper: 0,
                    }));
                }
            };
            if let Some(matched) = candidate {
                record_search_match(matched, &mut actual, meter)?;
                return finish_search(Some(matched), actual, upper);
            }
            cursor = anchor_start
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "rejected search anchor progress",
                })?;
        }
    }

    fn search_suffix_inside_class(
        &self,
        haystack: &[u8],
        projection: SearchProjection,
        upper: ReduceUpperBounds,
        meter: SearchMeter,
    ) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
        debug_assert_eq!(self.geometry, ResolvedSearchGeometry::SuffixInsideClass);
        debug_assert!(self.prefix().is_empty());
        let suffix_bytes = self.anchor.needle().len();
        let mut actual = new_search_actual();
        let mut cursor = 0_usize;
        loop {
            let Some((first_suffix, first_suffix_end)) =
                self.next_anchor(haystack, cursor, haystack.len(), &mut actual, meter)?
            else {
                return finish_search(None, actual, upper);
            };
            let run_start = search_scan_class_run_backward(
                haystack,
                self.class,
                self.ascii_scanner.as_ref(),
                first_suffix,
                &mut actual,
                meter,
            )?
            .unwrap_or(first_suffix);
            let run_end = search_scan_class_run_forward(
                haystack,
                self.class,
                self.ascii_scanner.as_ref(),
                first_suffix_end,
                &mut actual,
                meter,
            )?
            .unwrap_or(first_suffix_end);
            meter.ensure_work(&actual, RUN_WORK)?;
            actual.runs = checked_add(actual.runs, 1, "search class-suffix run count")?;
            actual.work = checked_add(actual.work, RUN_WORK, "search class-suffix run work")?;

            let mut chosen = (run_start < first_suffix).then_some(first_suffix);
            let mut overlap_cursor =
                first_suffix
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "search overlapping suffix restart",
                    })?;
            while (projection == SearchProjection::Selected || chosen.is_none())
                && run_end.saturating_sub(overlap_cursor) >= suffix_bytes
            {
                let Some((next_suffix, _)) =
                    self.next_anchor(haystack, overlap_cursor, run_end, &mut actual, meter)?
                else {
                    break;
                };
                chosen = Some(next_suffix);
                overlap_cursor =
                    next_suffix
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "next search overlapping suffix restart",
                        })?;
            }
            if let Some(suffix_start) = chosen {
                let end = suffix_start.checked_add(suffix_bytes).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "search class-suffix match end",
                    },
                )?;
                actual.candidates =
                    checked_add(actual.candidates, 1, "search class-suffix candidate count")?;
                let matched = (run_start, end);
                record_search_match(matched, &mut actual, meter)?;
                return finish_search(Some(matched), actual, upper);
            }
            cursor = run_end;
        }
    }

    fn search_complete_ascii_word_run(
        &self,
        original: &[u8],
        haystack: &[u8],
        window_start: usize,
        upper: ReduceUpperBounds,
        meter: SearchMeter,
    ) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
        debug_assert_eq!(
            self.geometry,
            ResolvedSearchGeometry::CompleteAsciiWordSuffix
        );
        let mut actual = new_search_actual();
        let mut cursor = 0_usize;
        loop {
            let Some((suffix_start, suffix_end)) =
                self.next_anchor(haystack, cursor, haystack.len(), &mut actual, meter)?
            else {
                return finish_search(None, actual, upper);
            };
            let absolute_suffix_end =
                window_start
                    .checked_add(suffix_end)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "absolute guarded suffix end",
                    })?;
            let next_is_word = if suffix_end < haystack.len() {
                self.class.contains(search_read_classified(
                    haystack,
                    suffix_end,
                    &mut actual,
                    meter,
                )?)
            } else if absolute_suffix_end < original.len() {
                self.class.contains(search_read_classified(
                    original,
                    absolute_suffix_end,
                    &mut actual,
                    meter,
                )?)
            } else {
                false
            };
            if next_is_word {
                cursor = suffix_start
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "embedded guarded search suffix progress",
                    })?;
                continue;
            }

            actual.candidates =
                checked_add(actual.candidates, 1, "guarded search candidate count")?;
            let Some(run_start) = search_scan_class_run_backward(
                haystack,
                self.class,
                self.ascii_scanner.as_ref(),
                suffix_start,
                &mut actual,
                meter,
            )?
            .filter(|&start| start < suffix_start) else {
                cursor = suffix_start
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "rejected guarded search suffix progress",
                    })?;
                continue;
            };
            meter.ensure_work(&actual, RUN_WORK)?;
            actual.runs = checked_add(actual.runs, 1, "guarded search run count")?;
            actual.work = checked_add(actual.work, RUN_WORK, "guarded search run work")?;

            let absolute_run_start =
                window_start
                    .checked_add(run_start)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "absolute guarded run start",
                    })?;
            if run_start == 0 && absolute_run_start != 0 {
                let previous =
                    absolute_run_start
                        .checked_sub(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "guarded original predecessor",
                        })?;
                if self.class.contains(search_read_classified(
                    original,
                    previous,
                    &mut actual,
                    meter,
                )?) {
                    cursor =
                        suffix_start
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "context-rejected guarded suffix progress",
                            })?;
                    continue;
                }
            }

            let matched = (run_start, suffix_end);
            record_search_match(matched, &mut actual, meter)?;
            return finish_search(Some(matched), actual, upper);
        }
    }

    fn next_anchor(
        &self,
        haystack: &[u8],
        cursor: usize,
        end: usize,
        actual: &mut ReduceActualCounters,
        meter: SearchMeter,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let anchor_bytes = self.anchor.needle().len();
        let remaining = end
            .checked_sub(cursor)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "search anchor remaining bytes",
            })?;
        if remaining < anchor_bytes {
            return Ok(None);
        }
        meter.ensure_work(actual, FINDER_CALL_WORK)?;
        actual.finder_calls = checked_add(actual.finder_calls, 1, "search finder calls")?;
        actual.work = checked_add(actual.work, FINDER_CALL_WORK, "search finder call work")?;
        let service_bytes = if meter.work_envelope_admitted {
            remaining
        } else {
            meter.service_capacity(actual, FINDER_SCAN_WORK)?
        };
        if service_bytes < anchor_bytes {
            let required = anchor_bytes.checked_mul(FINDER_SCAN_WORK).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "metered anchor minimum service work",
                },
            )?;
            meter.ensure_work(actual, required)?;
            return Err(SearchError::Kernel(ReduceError::AccountingInvariant {
                resource: "metered anchor minimum service",
                actual: 1,
                upper: 0,
            }));
        }
        let search_end = cursor.saturating_add(service_bytes).min(end);
        let search = haystack
            .get(cursor..search_end)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "search anchor window",
            })?;
        let Some(relative) = self.anchor.find(search) else {
            charge_finder_scan(actual, search.len())?;
            if search_end != end {
                meter.ensure_work(actual, FINDER_SCAN_WORK)?;
                return Err(SearchError::Kernel(ReduceError::AccountingInvariant {
                    resource: "metered anchor continuation",
                    actual: 1,
                    upper: 0,
                }));
            }
            return Ok(None);
        };
        let finder_service =
            relative
                .checked_add(anchor_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "successful search finder service",
                })?;
        charge_finder_scan(actual, finder_service)?;
        let start = cursor
            .checked_add(relative)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "search anchor start",
            })?;
        let anchor_end =
            start
                .checked_add(anchor_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "search anchor end",
                })?;
        meter.ensure_anchor_candidate(actual)?;
        meter.ensure_work(actual, ANCHOR_CANDIDATE_WORK)?;
        actual.anchor_candidates =
            checked_add(actual.anchor_candidates, 1, "search anchor candidates")?;
        actual.work = checked_add(
            actual.work,
            ANCHOR_CANDIDATE_WORK,
            "search anchor candidate work",
        )?;
        Ok(Some((start, anchor_end)))
    }

    fn preflight(
        &self,
        input_bytes: usize,
        operation: Operation,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let upper = self.reduce_upper_bounds(input_bytes, operation)?;
        enforce_upper_bounds(upper, limits)?;
        Ok(upper)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the source-free preflight keeps every finder, class, literal, result, and resource bound adjacent"
    )]
    fn reduce_upper_bounds(
        &self,
        input_bytes: usize,
        operation: Operation,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let class_scan = match self.ascii_scanner {
            Some(AsciiClassScanner::Fixed(_)) => ClassScanKind::Fixed,
            Some(AsciiClassScanner::Run(scanner)) => ClassScanKind::Run {
                max_classification_overhead: scanner.max_classification_overhead(),
            },
            None => ClassScanKind::Scalar,
        };
        match self.geometry {
            ResolvedSearchGeometry::GeneralPrefix | ResolvedSearchGeometry::GeneralSuffix => {
                derive_reduce_upper_bounds(self.build, class_scan, false, input_bytes, operation)
            }
            ResolvedSearchGeometry::SuffixInsideClass => {
                derive_reduce_upper_bounds(self.build, class_scan, true, input_bytes, operation)
            }
            ResolvedSearchGeometry::CompleteAsciiWordSuffix => {
                derive_complete_ascii_word_run_upper_bounds(
                    self.build,
                    class_scan,
                    input_bytes,
                    operation,
                )
            }
        }
    }

    /// Publish the exact source-free full-window count envelope retained by
    /// this plan, including its selected scalar or SIMD class scanner.
    pub fn count_upper_bounds(&self, input_bytes: usize) -> Result<ReduceUpperBounds, ReduceError> {
        self.reduce_upper_bounds(input_bytes, Operation::Count)
    }

    /// Publish the exact source-free full-window span-sum envelope retained by
    /// this plan, including its selected scalar or SIMD class scanner.
    pub fn span_sum_upper_bounds(
        &self,
        input_bytes: usize,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        self.reduce_upper_bounds(input_bytes, Operation::SpanSum)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the monotone anchor traversal keeps cumulative actual accounting adjacent to every source operation"
    )]
    fn scan(
        &self,
        haystack: &[u8],
        operation: Operation,
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        self.scan_with_visitor(haystack, operation, upper, &mut |_| {})
    }

    fn scan_with_visitor<F>(
        &self,
        haystack: &[u8],
        operation: Operation,
        upper: ReduceUpperBounds,
        visitor: &mut F,
    ) -> Result<ReduceActualCounters, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        match self.geometry {
            ResolvedSearchGeometry::CompleteAsciiWordSuffix => {
                return self.scan_complete_ascii_word_run(haystack, operation, upper, visitor);
            }
            ResolvedSearchGeometry::SuffixInsideClass => {
                return self.scan_suffix_inside_class(haystack, operation, upper, visitor);
            }
            ResolvedSearchGeometry::GeneralPrefix | ResolvedSearchGeometry::GeneralSuffix => {}
        }
        let mut actual = ReduceActualCounters {
            source_reads: 0,
            finder_scanned_bytes: 0,
            finder_calls: 0,
            anchor_candidates: 0,
            classifications: 0,
            literal_comparisons: 0,
            runs: 0,
            candidates: 0,
            matches: 0,
            count: 0,
            span_sum: 0,
            work: FIXED_REDUCE_WORK,
            scratch_bytes: 0,
        };
        let anchor_bytes = self.anchor.needle().len();
        if haystack.len() < anchor_bytes {
            verify_actual(actual, upper)?;
            return Ok(actual);
        }
        let mut cursor = 0_usize;
        let mut restart = 0_usize;
        loop {
            let remaining =
                haystack
                    .len()
                    .checked_sub(cursor)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "anchor search remaining bytes",
                    })?;
            if remaining < anchor_bytes {
                break;
            }
            let search = haystack
                .get(cursor..)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "anchor search window",
                })?;
            actual.finder_calls = checked_add(actual.finder_calls, 1, "actual finder calls")?;
            actual.work = checked_add(actual.work, FINDER_CALL_WORK, "finder call work")?;
            let Some(relative) = self.anchor.find(search) else {
                charge_finder_scan(&mut actual, search.len())?;
                break;
            };
            let finder_service =
                relative
                    .checked_add(anchor_bytes)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "successful finder service bytes",
                    })?;
            charge_finder_scan(&mut actual, finder_service)?;
            let anchor_start =
                cursor
                    .checked_add(relative)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "absolute anchor start",
                    })?;
            let anchor_end =
                anchor_start
                    .checked_add(anchor_bytes)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "absolute anchor end",
                    })?;
            actual.anchor_candidates =
                checked_add(actual.anchor_candidates, 1, "actual anchor candidates")?;
            actual.work = checked_add(actual.work, ANCHOR_CANDIDATE_WORK, "anchor candidate work")?;
            let candidate = match self.geometry {
                ResolvedSearchGeometry::GeneralPrefix => self.prefix_anchor_candidate(
                    haystack,
                    anchor_start,
                    anchor_end,
                    restart,
                    &mut actual,
                )?,
                ResolvedSearchGeometry::GeneralSuffix => self.suffix_anchor_candidate(
                    haystack,
                    anchor_start,
                    anchor_end,
                    restart,
                    &mut actual,
                )?,
                ResolvedSearchGeometry::SuffixInsideClass
                | ResolvedSearchGeometry::CompleteAsciiWordSuffix => {
                    return Err(ReduceError::AccountingInvariant {
                        resource: "resolved reduction dispatch",
                        actual: 1,
                        upper: 0,
                    });
                }
            };
            if let Some((start, end)) = candidate {
                record_reduce_match(&mut actual, operation, start, end, visitor)?;
                restart = end;
                cursor = end;
            } else {
                cursor = anchor_start
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "rejected overlapping anchor progress",
                    })?;
            }
        }
        actual.source_reads = actual
            .finder_scanned_bytes
            .checked_add(actual.classifications)
            .and_then(|reads| reads.checked_add(actual.literal_comparisons))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual source reads",
            })?;
        verify_actual(actual, upper)?;
        Ok(actual)
    }

    /// Reduce `CLASS+ SUFFIX` when every suffix byte is itself a class member.
    ///
    /// The first suffix occurrence identifies one maximal class run. Span-sum
    /// recovers the run start; both operations probe the byte after the suffix
    /// before retaining a forward scanner. Count only needs to prove that some
    /// suffix in the run has a class predecessor, while span-sum selects the
    /// last suffix for greedy repetition semantics. A valid run contributes
    /// at most one match, and the cursor skips to the proved run end.
    #[allow(
        clippy::too_many_lines,
        reason = "grouped suffix discovery keeps the shared count/span accounting adjacent to every sparse source operation"
    )]
    fn scan_suffix_inside_class<F>(
        &self,
        haystack: &[u8],
        operation: Operation,
        upper: ReduceUpperBounds,
        visitor: &mut F,
    ) -> Result<ReduceActualCounters, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        let mut actual = ReduceActualCounters {
            source_reads: 0,
            finder_scanned_bytes: 0,
            finder_calls: 0,
            anchor_candidates: 0,
            classifications: 0,
            literal_comparisons: 0,
            runs: 0,
            candidates: 0,
            matches: 0,
            count: 0,
            span_sum: 0,
            work: FIXED_REDUCE_WORK,
            scratch_bytes: 0,
        };
        let suffix_bytes = self.anchor.needle().len();
        debug_assert_eq!(self.geometry, ResolvedSearchGeometry::SuffixInsideClass);
        debug_assert!(self.prefix().is_empty());
        debug_assert!(suffix_bytes != 0);
        let mut cursor = 0_usize;
        loop {
            let remaining =
                haystack
                    .len()
                    .checked_sub(cursor)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "class-suffix search remaining bytes",
                    })?;
            if remaining < suffix_bytes {
                break;
            }
            let search = haystack
                .get(cursor..)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "class-suffix search window",
                })?;
            actual.finder_calls = checked_add(actual.finder_calls, 1, "actual finder calls")?;
            actual.work = checked_add(actual.work, FINDER_CALL_WORK, "finder call work")?;
            let Some(relative) = self.anchor.find(search) else {
                charge_finder_scan(&mut actual, search.len())?;
                break;
            };
            let finder_service =
                relative
                    .checked_add(suffix_bytes)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "class-suffix successful finder service",
                    })?;
            charge_finder_scan(&mut actual, finder_service)?;
            let first_suffix =
                cursor
                    .checked_add(relative)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "first suffix in class run",
                    })?;
            let first_suffix_end =
                first_suffix
                    .checked_add(suffix_bytes)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "first suffix end in class run",
                    })?;
            actual.anchor_candidates =
                checked_add(actual.anchor_candidates, 1, "actual anchor candidates")?;
            actual.work = checked_add(actual.work, ANCHOR_CANDIDATE_WORK, "anchor candidate work")?;

            let (run_start, mut has_class_prefix) = if matches!(
                operation,
                Operation::SpanSum | Operation::SpanVisit
            ) {
                let start = scan_class_run_backward(
                    haystack,
                    self.class,
                    self.ascii_scanner.as_ref(),
                    first_suffix,
                    &mut actual,
                )?
                .unwrap_or(first_suffix);
                (start, start < first_suffix)
            } else {
                let has_class_prefix = if let Some(previous) = first_suffix.checked_sub(1) {
                    self.class
                        .contains(read_classified(haystack, previous, &mut actual)?)
                } else {
                    false
                };
                (first_suffix, has_class_prefix)
            };
            let next_is_class = if first_suffix_end < haystack.len() {
                Some(
                    self.class
                        .contains(read_classified(haystack, first_suffix_end, &mut actual)?),
                )
            } else {
                None
            };
            let run_end = match next_is_class {
                Some(true) => {
                    let after_proved_member =
                        first_suffix_end
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "class-suffix proved member advance",
                            })?;
                    scan_class_run_forward(
                        haystack,
                        self.class,
                        self.ascii_scanner.as_ref(),
                        after_proved_member,
                        &mut actual,
                    )?
                    .unwrap_or(after_proved_member)
                }
                None | Some(false) => first_suffix_end,
            };
            actual.runs = checked_add(actual.runs, 1, "actual run count")?;
            actual.work = checked_add(actual.work, RUN_WORK, "actual run work")?;

            let mut last_suffix = first_suffix;
            if !has_class_prefix
                || matches!(operation, Operation::SpanSum | Operation::SpanVisit)
            {
                let mut overlap_cursor =
                    first_suffix
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "overlapping suffix restart",
                        })?;
                while run_end.saturating_sub(overlap_cursor) >= suffix_bytes {
                    let run_search = haystack.get(overlap_cursor..run_end).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "overlapping suffix run window",
                        },
                    )?;
                    actual.finder_calls =
                        checked_add(actual.finder_calls, 1, "actual finder calls")?;
                    actual.work = checked_add(actual.work, FINDER_CALL_WORK, "finder call work")?;
                    let Some(relative) = self.anchor.find(run_search) else {
                        charge_finder_scan(&mut actual, run_search.len())?;
                        break;
                    };
                    let finder_service = relative.checked_add(suffix_bytes).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "overlapping suffix finder service",
                        },
                    )?;
                    charge_finder_scan(&mut actual, finder_service)?;
                    last_suffix = overlap_cursor.checked_add(relative).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "last suffix in class run",
                        },
                    )?;
                    actual.anchor_candidates =
                        checked_add(actual.anchor_candidates, 1, "actual anchor candidates")?;
                    actual.work =
                        checked_add(actual.work, ANCHOR_CANDIDATE_WORK, "anchor candidate work")?;
                    has_class_prefix = true;
                    if operation == Operation::Count {
                        break;
                    }
                    overlap_cursor =
                        last_suffix
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "next overlapping suffix restart",
                            })?;
                }
            }

            if has_class_prefix {
                let end = last_suffix.checked_add(suffix_bytes).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "greedy class-suffix match end",
                    },
                )?;
                actual.candidates = checked_add(actual.candidates, 1, "actual candidate count")?;
                record_reduce_match(&mut actual, operation, run_start, end, visitor)?;
            }
            cursor = run_end;
        }
        actual.source_reads = actual
            .finder_scanned_bytes
            .checked_add(actual.classifications)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "class-suffix finder and class source reads",
            })?;
        verify_actual(actual, upper)?;
        Ok(actual)
    }

    /// Search overlapping suffix occurrences and prove only the two ASCII
    /// word-boundary conditions that are not already implied by the suffix.
    ///
    /// Embedded suffix occurrences advance by one byte so a later overlapping
    /// terminal occurrence remains visible. Accepted matches advance to the
    /// suffix end, preserving Rust's non-overlapping iteration. Count needs
    /// only the preceding-byte probe; span sum alone recovers the maximal run
    /// start with the retained backward scanner.
    #[allow(
        clippy::too_many_lines,
        reason = "the guarded monotone traversal keeps every source probe, overlap restart, and actual accounting charge adjacent"
    )]
    fn scan_complete_ascii_word_run<F>(
        &self,
        haystack: &[u8],
        operation: Operation,
        upper: ReduceUpperBounds,
        visitor: &mut F,
    ) -> Result<ReduceActualCounters, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        debug_assert_eq!(
            self.geometry,
            ResolvedSearchGeometry::CompleteAsciiWordSuffix
        );
        debug_assert!(self.opposite_literal.is_empty());
        let mut actual = ReduceActualCounters {
            source_reads: 0,
            finder_scanned_bytes: 0,
            finder_calls: 0,
            anchor_candidates: 0,
            classifications: 0,
            literal_comparisons: 0,
            runs: 0,
            candidates: 0,
            matches: 0,
            count: 0,
            span_sum: 0,
            work: FIXED_REDUCE_WORK,
            scratch_bytes: 0,
        };
        let suffix_bytes = self.anchor.needle().len();
        if haystack.len() < suffix_bytes {
            verify_actual(actual, upper)?;
            return Ok(actual);
        }

        let mut cursor = 0_usize;
        loop {
            let remaining =
                haystack
                    .len()
                    .checked_sub(cursor)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "guarded suffix search remaining bytes",
                    })?;
            if remaining < suffix_bytes {
                break;
            }
            let search = haystack
                .get(cursor..)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "guarded suffix search window",
                })?;
            actual.finder_calls = checked_add(actual.finder_calls, 1, "actual finder calls")?;
            actual.work = checked_add(actual.work, FINDER_CALL_WORK, "finder call work")?;
            let Some(relative) = self.anchor.find(search) else {
                charge_finder_scan(&mut actual, search.len())?;
                break;
            };
            let finder_service =
                relative
                    .checked_add(suffix_bytes)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "successful guarded finder service bytes",
                    })?;
            charge_finder_scan(&mut actual, finder_service)?;
            let start = cursor
                .checked_add(relative)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "absolute guarded suffix start",
                })?;
            let end = start
                .checked_add(suffix_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "absolute guarded suffix end",
                })?;
            actual.anchor_candidates =
                checked_add(actual.anchor_candidates, 1, "actual anchor candidates")?;
            actual.work = checked_add(actual.work, ANCHOR_CANDIDATE_WORK, "anchor candidate work")?;

            if end < haystack.len() {
                let next = read_classified(haystack, end, &mut actual)?;
                if self.class.contains(next) {
                    cursor = start
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "embedded guarded suffix progress",
                        })?;
                    continue;
                }
            }

            actual.candidates = checked_add(actual.candidates, 1, "actual candidate count")?;
            let match_start = match operation {
                Operation::Count => {
                    if start == 0 {
                        None
                    } else {
                        let previous =
                            start
                                .checked_sub(1)
                                .ok_or(ReduceError::ArithmeticOverflow {
                                    computation: "guarded suffix preceding position",
                                })?;
                        let byte = read_classified(haystack, previous, &mut actual)?;
                        self.class.contains(byte).then_some(start)
                    }
                }
                Operation::SpanSum | Operation::SpanVisit => {
                    if start == 0 {
                        None
                    } else {
                        let recovered = scan_class_run_backward(
                            haystack,
                            self.class,
                            self.ascii_scanner.as_ref(),
                            start,
                            &mut actual,
                        )?;
                        if let Some(run_start) = recovered.filter(|&run_start| run_start < start) {
                            actual.runs = checked_add(actual.runs, 1, "actual run count")?;
                            actual.work = checked_add(actual.work, RUN_WORK, "actual run work")?;
                            Some(run_start)
                        } else {
                            None
                        }
                    }
                }
            };

            if let Some(match_start) = match_start {
                record_reduce_match(&mut actual, operation, match_start, end, visitor)?;
                cursor = end;
            } else {
                cursor = start
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "rejected guarded suffix progress",
                    })?;
            }
        }
        actual.source_reads = actual
            .finder_scanned_bytes
            .checked_add(actual.classifications)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "guarded finder and class source reads",
            })?;
        verify_actual(actual, upper)?;
        Ok(actual)
    }

    fn prefix_anchor_candidate(
        &self,
        haystack: &[u8],
        anchor_start: usize,
        anchor_end: usize,
        restart: usize,
        actual: &mut ReduceActualCounters,
    ) -> Result<Option<(usize, usize)>, ReduceError> {
        let Some(run_end) = scan_class_run_forward(
            haystack,
            self.class,
            self.ascii_scanner.as_ref(),
            anchor_end,
            actual,
        )?
        else {
            return Ok(None);
        };
        actual.runs = checked_add(actual.runs, 1, "actual run count")?;
        actual.work = checked_add(actual.work, RUN_WORK, "actual run work")?;
        let end =
            run_end
                .checked_add(self.suffix().len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "prefix-anchor candidate end",
                })?;
        if anchor_start < restart || end > haystack.len() {
            return Ok(None);
        }
        actual.candidates = checked_add(actual.candidates, 1, "actual candidate count")?;
        if !literal_equals(haystack, run_end, self.suffix(), actual)? {
            return Ok(None);
        }
        Ok(Some((anchor_start, end)))
    }

    fn suffix_anchor_candidate(
        &self,
        haystack: &[u8],
        anchor_start: usize,
        anchor_end: usize,
        restart: usize,
        actual: &mut ReduceActualCounters,
    ) -> Result<Option<(usize, usize)>, ReduceError> {
        let Some(run_start) = scan_class_run_backward(
            haystack,
            self.class,
            self.ascii_scanner.as_ref(),
            anchor_start,
            actual,
        )?
        else {
            return Ok(None);
        };
        actual.runs = checked_add(actual.runs, 1, "actual run count")?;
        actual.work = checked_add(actual.work, RUN_WORK, "actual run work")?;
        let start = if self.prefix().is_empty() {
            let start = run_start.max(restart);
            if start >= anchor_start {
                return Ok(None);
            }
            start
        } else {
            let Some(start) = run_start.checked_sub(self.prefix().len()) else {
                return Ok(None);
            };
            if start < restart {
                return Ok(None);
            }
            start
        };
        actual.candidates = checked_add(actual.candidates, 1, "actual candidate count")?;
        if !literal_equals(haystack, start, self.prefix(), actual)? {
            return Ok(None);
        }
        Ok(Some((start, anchor_end)))
    }

    fn search_prefix_anchor_candidate(
        &self,
        haystack: &[u8],
        anchor_start: usize,
        anchor_end: usize,
        restart: usize,
        actual: &mut ReduceActualCounters,
        meter: SearchMeter,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let Some(run_end) = search_scan_class_run_forward(
            haystack,
            self.class,
            self.ascii_scanner.as_ref(),
            anchor_end,
            actual,
            meter,
        )?
        else {
            return Ok(None);
        };
        meter.ensure_work(actual, RUN_WORK)?;
        actual.runs = checked_add(actual.runs, 1, "actual run count")?;
        actual.work = checked_add(actual.work, RUN_WORK, "actual run work")?;
        let end =
            run_end
                .checked_add(self.suffix().len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "prefix-anchor candidate end",
                })?;
        if anchor_start < restart || end > haystack.len() {
            return Ok(None);
        }
        actual.candidates = checked_add(actual.candidates, 1, "actual candidate count")?;
        if !search_literal_equals(haystack, run_end, self.suffix(), actual, meter)? {
            return Ok(None);
        }
        Ok(Some((anchor_start, end)))
    }

    fn search_prefix_anchor_shortest_candidate(
        &self,
        haystack: &[u8],
        anchor_start: usize,
        anchor_end: usize,
        actual: &mut ReduceActualCounters,
        meter: SearchMeter,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        debug_assert!(self.suffix().is_empty());
        let Some(&byte) = haystack.get(anchor_end) else {
            return Ok(None);
        };
        meter.ensure_work(actual, CLASSIFICATION_WORK)?;
        actual.classifications =
            checked_add(actual.classifications, 1, "shortest classification count")?;
        actual.work = checked_add(
            actual.work,
            CLASSIFICATION_WORK,
            "shortest classification work",
        )?;
        if !self.class.contains(byte) {
            return Ok(None);
        }
        meter.ensure_work(actual, RUN_WORK)?;
        actual.runs = checked_add(actual.runs, 1, "shortest run count")?;
        actual.work = checked_add(actual.work, RUN_WORK, "shortest run work")?;
        actual.candidates = checked_add(actual.candidates, 1, "shortest candidate count")?;
        let end = anchor_end
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "shortest prefix-only match end",
            })?;
        Ok(Some((anchor_start, end)))
    }

    fn search_suffix_anchor_candidate(
        &self,
        haystack: &[u8],
        anchor_start: usize,
        anchor_end: usize,
        restart: usize,
        actual: &mut ReduceActualCounters,
        meter: SearchMeter,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let Some(run_start) = search_scan_class_run_backward(
            haystack,
            self.class,
            self.ascii_scanner.as_ref(),
            anchor_start,
            actual,
            meter,
        )?
        else {
            return Ok(None);
        };
        meter.ensure_work(actual, RUN_WORK)?;
        actual.runs = checked_add(actual.runs, 1, "actual run count")?;
        actual.work = checked_add(actual.work, RUN_WORK, "actual run work")?;
        let start = if self.prefix().is_empty() {
            let start = run_start.max(restart);
            if start >= anchor_start {
                return Ok(None);
            }
            start
        } else {
            let Some(start) = run_start.checked_sub(self.prefix().len()) else {
                return Ok(None);
            };
            if start < restart {
                return Ok(None);
            }
            start
        };
        actual.candidates = checked_add(actual.candidates, 1, "actual candidate count")?;
        if !search_literal_equals(haystack, start, self.prefix(), actual, meter)? {
            return Ok(None);
        }
        Ok(Some((start, anchor_end)))
    }
}

impl LiteralClassRunSearchPlan {
    pub fn build<I>(
        prefix: &[u8],
        ranges: I,
        suffix: &[u8],
        minimum: SearchRunMinimum,
        boundary_semantics: BoundarySemantics,
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_inner(
            None,
            prefix,
            ranges,
            None,
            suffix,
            minimum,
            boundary_semantics,
            false,
            limits,
        )
    }

    /// Build with one immutable host-capability snapshot.
    pub fn build_with_dispatch<I>(
        dispatch: SimdDispatchContext,
        prefix: &[u8],
        ranges: I,
        suffix: &[u8],
        minimum: SearchRunMinimum,
        boundary_semantics: BoundarySemantics,
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_inner(
            Some((dispatch, DispatchPolicy::Auto)),
            prefix,
            ranges,
            None,
            suffix,
            minimum,
            boundary_semantics,
            false,
            limits,
        )
    }

    /// Build a search plan for a canonical Unicode scalar class that contains
    /// every non-ASCII scalar. The retained byte set represents only the
    /// class's ASCII members; execution validates non-ASCII UTF-8 before
    /// treating those scalars as members.
    pub fn build_unicode_all_non_ascii_with_dispatch<I>(
        dispatch: SimdDispatchContext,
        prefix: &[u8],
        ranges: I,
        suffix: &[u8],
        minimum: SearchRunMinimum,
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (char, char)>,
    {
        let fixed_work = preflight_unicode_class_proof(prefix, suffix, limits)?;
        let prepared = prove_unicode_all_non_ascii_class(ranges, limits, fixed_work)?;
        Self::build_inner(
            Some((dispatch, DispatchPolicy::Auto)),
            prefix,
            core::iter::empty(),
            Some(prepared),
            suffix,
            minimum,
            BoundarySemantics::Unguarded,
            true,
            limits,
        )
    }

    #[cfg(test)]
    fn build_unicode_all_non_ascii<I>(
        prefix: &[u8],
        ranges: I,
        suffix: &[u8],
        minimum: SearchRunMinimum,
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (char, char)>,
    {
        let fixed_work = preflight_unicode_class_proof(prefix, suffix, limits)?;
        let prepared = prove_unicode_all_non_ascii_class(ranges, limits, fixed_work)?;
        Self::build_inner(
            None,
            prefix,
            core::iter::empty(),
            Some(prepared),
            suffix,
            minimum,
            BoundarySemantics::Unguarded,
            true,
            limits,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the search-only builder keeps semantic mode, structural revalidation, and every exact resource charge adjacent"
    )]
    fn build_inner<I>(
        dispatch: Option<(SimdDispatchContext, DispatchPolicy)>,
        prefix: &[u8],
        mut ranges: I,
        prepared_class: Option<PreparedClass>,
        suffix: &[u8],
        minimum: SearchRunMinimum,
        boundary_semantics: BoundarySemantics,
        unicode_all_non_ascii: bool,
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        match boundary_semantics {
            BoundarySemantics::Unguarded if prefix.is_empty() => {
                return Err(BuildError::EmptyPrefix);
            }
            BoundarySemantics::CompleteAsciiWordRun if !prefix.is_empty() => {
                return Err(BuildError::NonEmptyPrefixForCompleteAsciiWordRun);
            }
            BoundarySemantics::CompleteAsciiWordRun if suffix.is_empty() => {
                return Err(BuildError::EmptySuffix);
            }
            BoundarySemantics::CompleteAsciiWordRun if minimum != SearchRunMinimum::One => {
                return Err(BuildError::UnsupportedSearchMinimum);
            }
            BoundarySemantics::Unguarded | BoundarySemantics::CompleteAsciiWordRun => {}
        }
        if unicode_all_non_ascii && suffix.is_empty() {
            return Err(BuildError::EmptySuffix);
        }

        let literal_bytes =
            prefix
                .len()
                .checked_add(suffix.len())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "generalized search literal byte total",
                })?;
        enforce_build(
            literal_bytes,
            limits.max_literal_bytes,
            BuildResource::LiteralBytes,
        )?;
        let anchor_bytes = match boundary_semantics {
            BoundarySemantics::Unguarded => prefix.len(),
            BoundarySemantics::CompleteAsciiWordRun => suffix.len(),
        };
        let scratch_bytes = 0;
        let persistent_bytes =
            size_of::<Self>()
                .checked_add(literal_bytes)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "generalized search persistent bytes",
                })?;
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

        let literal_work = literal_bytes
            .checked_mul(LITERAL_BUILD_WORK_PER_BYTE)
            .and_then(|value| {
                anchor_bytes
                    .checked_mul(FINDER_BUILD_WORK_PER_BYTE)
                    .and_then(|finder| value.checked_add(finder))
            })
            .and_then(|value| value.checked_add(FIXED_BUILD_WORK))
            .and_then(|value| value.checked_add(ANCHOR_SELECTION_WORK))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "generalized search fixed build work",
            })?;
        let mut actual = DirectBuildAttemptActual::default();
        let (class, class_ranges, class_members, ascii_scanner, work_upper_bound) = {
            let mut work = BuildWork::new(limits.max_build_work, &mut actual);
            work.charge(literal_work)?;
            let (class, class_ranges, class_members) = if let Some(prepared) = prepared_class {
                work.charge(prepared.work)?;
                (
                    prepared.class,
                    prepared.input_ranges,
                    prepared.materialized_members,
                )
            } else {
                build_class(&mut ranges, limits, &mut work)?
            };
            match boundary_semantics {
                BoundarySemantics::Unguarded => {
                    work.charge(1)?;
                    if suffix
                        .first()
                        .is_some_and(|&boundary| class.contains(boundary))
                    {
                        return Err(BuildError::SuffixBoundaryInClass);
                    }
                }
                BoundarySemantics::CompleteAsciiWordRun => {
                    work.charge(1)?;
                    if !class.is_ascii_word_subset() {
                        return Err(BuildError::ClassOutsideAsciiWord);
                    }
                    for &byte in suffix {
                        work.charge(1)?;
                        if !is_ascii_word(byte) {
                            return Err(BuildError::SuffixByteOutsideAsciiWord);
                        }
                    }
                }
            }
            let ascii_scanner = build_ascii_scanner(
                dispatch.filter(|_| class.is_ascii()),
                class,
                unicode_all_non_ascii,
                &mut work,
            )?;
            (class, class_ranges, class_members, ascii_scanner, work.used)
        };

        let prefix = copy_literal(prefix, "generalized search prefix")?;
        if !prefix.is_empty() {
            record_literal_copy(&mut actual, prefix.len())?;
        }
        let suffix = copy_literal(suffix, "generalized search suffix")?;
        if !suffix.is_empty() {
            record_literal_copy(&mut actual, suffix.len())?;
        }
        let prefix_bytes = prefix.len();
        let suffix_bytes = suffix.len();
        let (anchor_kind, anchor, opposite_literal) = match boundary_semantics {
            BoundarySemantics::Unguarded => (
                Anchor::Prefix,
                FinderBuilder::new().build_forward_owned(prefix),
                suffix,
            ),
            BoundarySemantics::CompleteAsciiWordRun => (
                Anchor::CompleteAsciiWordSuffix,
                FinderBuilder::new().build_forward_owned(suffix),
                prefix,
            ),
        };
        Ok(Self {
            anchor,
            opposite_literal,
            anchor_kind,
            class,
            ascii_scanner,
            minimum,
            unicode_all_non_ascii,
            build: BuildAccounting {
                prefix_bytes,
                suffix_bytes,
                literal_bytes,
                class_ranges,
                class_members,
                work_upper_bound,
                scratch_bytes,
                persistent_bytes,
                peak_bytes,
            },
        })
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    #[must_use]
    pub const fn plan_id(&self) -> &'static str {
        if self.unicode_all_non_ascii {
            UNICODE_ALL_NON_ASCII_SEARCH_PLAN_ID
        } else {
            GENERAL_SEARCH_PLAN_ID
        }
    }

    #[must_use]
    pub const fn boundary_semantics(&self) -> BoundarySemantics {
        match self.anchor_kind {
            Anchor::Prefix | Anchor::Suffix => BoundarySemantics::Unguarded,
            Anchor::CompleteAsciiWordSuffix => BoundarySemantics::CompleteAsciiWordRun,
        }
    }

    fn prefix(&self) -> &[u8] {
        match self.anchor_kind {
            Anchor::Prefix => self.anchor.needle(),
            Anchor::Suffix | Anchor::CompleteAsciiWordSuffix => &self.opposite_literal,
        }
    }

    fn suffix(&self) -> &[u8] {
        match self.anchor_kind {
            Anchor::Prefix => &self.opposite_literal,
            Anchor::Suffix | Anchor::CompleteAsciiWordSuffix => self.anchor.needle(),
        }
    }

    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.find_window(haystack, Window::full(haystack), limits)
    }

    pub fn find_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.search_window(haystack, window, limits, SearchProjection::Selected)
    }

    pub fn shortest(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.shortest_window(haystack, Window::full(haystack), limits)
    }

    pub fn shortest_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        let (matched, accounting) =
            self.search_window(haystack, window, limits, SearchProjection::EarliestEnd)?;
        Ok((matched.map(|(_, end)| end), accounting))
    }

    /// Return the selected ordinary full-haystack span without retaining
    /// window or diagnostic accounting machinery. All explicit-resource and
    /// stateful APIs continue to use [`Self::find_window_value`] or
    /// [`Self::find_window`].
    #[doc(hidden)]
    #[inline]
    pub fn find_ascii_word_suffix_full_ordinary_value(
        &self,
        haystack: &[u8],
    ) -> Result<Option<(usize, usize)>, SearchError> {
        debug_assert_eq!(self.anchor_kind, Anchor::CompleteAsciiWordSuffix);
        Ok(self.search_ascii_word_suffix_selected_value(haystack))
    }

    /// Return the earliest accepting end without retaining diagnostic
    /// accounting when selected and earliest-end search share one loop.
    #[inline]
    pub fn shortest_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<Option<usize>, SearchError> {
        if self.suffix().is_empty()
            || self.boundary_semantics() != BoundarySemantics::Unguarded
            || limits != SearchLimits::unlimited()
        {
            return self
                .shortest_window(haystack, window, limits)
                .map(|(matched, _)| matched);
        }
        self.find_window_value(haystack, window, limits)
            .map(|matched| matched.map(|(_, end)| end))
    }

    /// Return the selected match without retaining diagnostic accounting when
    /// the complete unguarded search envelope is admitted.
    #[inline]
    pub fn find_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(SearchError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        if self.boundary_semantics() != BoundarySemantics::Unguarded
            || limits != SearchLimits::unlimited()
        {
            return self
                .find_window(haystack, window, limits)
                .map(|(matched, _)| matched);
        }
        let (upper, _, _, meter) = self.search_preflight(haystack.len(), window, limits)?;
        if !meter.work_envelope_admitted
            || upper.anchor_candidates > limits.max_candidate_visits
        {
            return self
                .find_window(haystack, window, limits)
                .map(|(matched, _)| matched);
        }
        let slice = &haystack[window.start()..window.end()];
        self.search_prefix_selected_value(slice)
            .map(|(start, end)| {
                Ok::<(usize, usize), ReduceError>((
                    window.start().checked_add(start).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "absolute generalized value match start",
                        },
                    )?,
                    window.start().checked_add(end).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "absolute generalized value match end",
                        },
                    )?,
                ))
            })
            .transpose()
            .map_err(SearchError::from)
    }

    /// Whether any selected match exists without constructing diagnostic
    /// accounting on the success path.
    ///
    /// Once both source-independent execution envelopes fit the caller's
    /// limits, the unguarded route can execute without prospective metering:
    /// every possible finder, classification, comparison, and candidate
    /// event has already been admitted. Finite envelopes retain the ordinary
    /// metered search so refusal remains exact at the next charged event.
    pub fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        if self.boundary_semantics() != BoundarySemantics::Unguarded {
            return self
                .shortest_window(haystack, window, limits)
                .map(|(matched, _)| matched.is_some());
        }
        let (upper, _, _, meter) = self.search_preflight(haystack.len(), window, limits)?;
        if meter.work_envelope_admitted
            && upper.anchor_candidates <= limits.max_candidate_visits
        {
            let slice =
                haystack
                    .get(window.start()..window.end())
                    .ok_or(SearchError::InvalidWindow {
                        start: window.start(),
                        end: window.end(),
                        haystack_len: haystack.len(),
                    })?;
            return Ok(self.search_prefix_exists_value(slice));
        }
        self.shortest_window(haystack, window, limits)
            .map(|(matched, _)| matched.is_some())
    }

    fn search_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
        projection: SearchProjection,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        let (upper, window_bytes, assertion_context_bytes, meter) =
            self.search_preflight(haystack.len(), window, limits)?;
        let slice =
            haystack
                .get(window.start()..window.end())
                .ok_or(SearchError::InvalidWindow {
                    start: window.start(),
                    end: window.end(),
                    haystack_len: haystack.len(),
                })?;
        let (matched, actual) = match self.boundary_semantics() {
            BoundarySemantics::Unguarded => self.search_prefix(slice, projection, upper, meter)?,
            BoundarySemantics::CompleteAsciiWordRun => {
                self.search_ascii_word_suffix(haystack, slice, window.start(), upper, meter)?
            }
        };
        let matched =
            matched
                .map(|(start, end)| {
                    let start = window.start().checked_add(start).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "absolute generalized search match start",
                        },
                    )?;
                    let end =
                        window
                            .start()
                            .checked_add(end)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "absolute generalized search match end",
                            })?;
                    Ok::<(usize, usize), ReduceError>((start, end))
                })
                .transpose()?;
        let operation_id = match (self.unicode_all_non_ascii, projection) {
            (true, SearchProjection::Selected) => UNICODE_ALL_NON_ASCII_SEARCH_OPERATION_ID,
            (true, SearchProjection::EarliestEnd) => {
                UNICODE_ALL_NON_ASCII_SHORTEST_SEARCH_OPERATION_ID
            }
            (false, SearchProjection::Selected) => GENERAL_SEARCH_OPERATION_ID,
            (false, SearchProjection::EarliestEnd) => GENERAL_SHORTEST_SEARCH_OPERATION_ID,
        };
        Ok((
            matched,
            SearchAccounting {
                operation_id,
                window_bytes,
                assertion_context_bytes,
                candidate_visits_upper_bound: upper.anchor_candidates,
                source_reads_upper_bound: upper.source_reads,
                work_upper_bound: u64::try_from(upper.work).unwrap_or(u64::MAX),
                scratch_bytes: upper.scratch_bytes,
                candidate_visits: actual.anchor_candidates,
                finder_calls: actual.finder_calls,
                classifications: actual.classifications,
                literal_comparisons: actual.literal_comparisons,
                source_reads: actual.source_reads,
                work: actual.work,
            },
        ))
    }

    #[allow(
        clippy::inline_always,
        reason = "retaining the established search body avoids outlining this newly shared preflight"
    )]
    #[inline(always)]
    fn search_preflight(
        &self,
        haystack_len: usize,
        window: Window,
        limits: SearchLimits,
    ) -> Result<(ReduceUpperBounds, usize, usize, SearchMeter), SearchError> {
        if window.start() > window.end() || window.end() > haystack_len {
            return Err(SearchError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len,
            });
        }
        let window_bytes =
            window
                .end()
                .checked_sub(window.start())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "generalized search window bytes",
                })?;
        let assertion_context_bytes =
            if self.boundary_semantics() == BoundarySemantics::CompleteAsciiWordRun {
                usize::from(window.start() != 0) + usize::from(window.end() != haystack_len)
            } else {
                0
            };
        let accounted_bytes = window_bytes.checked_add(assertion_context_bytes).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "generalized search window plus assertion context",
            },
        )?;
        let upper = self.search_upper_bounds(accounted_bytes)?;
        if upper.scratch_bytes > limits.max_scratch_bytes {
            return Err(SearchError::ScratchLimit {
                needed: upper.scratch_bytes,
                limit: limits.max_scratch_bytes,
            });
        }
        let meter = SearchMeter::new(upper, limits)?;
        Ok((upper, window_bytes, assertion_context_bytes, meter))
    }

    #[allow(
        clippy::inline_always,
        reason = "the established search body already inlined these source-independent bounds"
    )]
    #[inline(always)]
    fn search_upper_bounds(&self, input_bytes: usize) -> Result<ReduceUpperBounds, ReduceError> {
        let anchor_bytes = self.anchor.needle().len();
        let anchor_candidates = input_bytes
            .checked_sub(anchor_bytes)
            .and_then(|remaining| remaining.checked_add(1))
            .unwrap_or(0);
        let overlap_service = anchor_candidates
            .checked_mul(anchor_bytes.saturating_sub(1))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "generalized overlapping finder service",
            })?;
        let finder_scanned_bytes =
            input_bytes
                .checked_add(overlap_service)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "generalized complete finder service",
                })?;
        // Prefix candidates whose repeated runs share one end are skipped as
        // a group. Guarded suffix candidates recover at most one class run
        // per terminal word suffix. Thus logical class traversal is linear.
        //
        // For an implicit-high Unicode class, let K be the number of
        // nonempty initial or resumed ASCII scanner calls. Their starts are
        // strictly increasing in the post-prefix domain, including across a
        // failed suffix restart, so K <= anchor_candidates. Scalar decoding
        // and run intervals contribute at most 4 * input_bytes logical
        // classifications, a scanner terminal may be decoded once more, and
        // every scanner call may physically inspect at most one partial wide
        // block. Therefore the retained expression covers
        // 4N + K + K * (ASCII_WIDE_BYTES - 1).
        let logical_classifications = input_bytes
            .checked_mul(4)
            .and_then(|value| value.checked_add(anchor_candidates))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "generalized logical classifications",
            })?;
        let classifications = anchor_candidates
            .checked_mul(ASCII_WIDE_BYTES - 1)
            .and_then(|overhead| logical_classifications.checked_add(overhead))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "generalized physical classifications",
            })?;
        let literal_comparisons = if self.anchor_kind == Anchor::Prefix {
            anchor_candidates.checked_mul(self.suffix().len()).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "generalized suffix comparisons",
                },
            )?
        } else {
            0
        };
        let source_reads = finder_scanned_bytes
            .checked_add(classifications)
            .and_then(|value| value.checked_add(literal_comparisons))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "generalized source reads",
            })?;
        let work = finder_scanned_bytes
            .checked_mul(FINDER_SCAN_WORK)
            .and_then(|value| {
                anchor_candidates
                    .checked_mul(FINDER_CALL_WORK)
                    .and_then(|calls| value.checked_add(calls))
            })
            .and_then(|value| {
                anchor_candidates
                    .checked_mul(ANCHOR_CANDIDATE_WORK)
                    .and_then(|candidates| value.checked_add(candidates))
            })
            .and_then(|value| {
                classifications
                    .checked_mul(CLASSIFICATION_WORK)
                    .and_then(|classified| value.checked_add(classified))
            })
            .and_then(|value| {
                literal_comparisons
                    .checked_mul(LITERAL_COMPARISON_WORK)
                    .and_then(|compared| value.checked_add(compared))
            })
            .and_then(|value| {
                anchor_candidates
                    .checked_mul(RUN_WORK)
                    .and_then(|runs| value.checked_add(runs))
            })
            .and_then(|value| {
                anchor_candidates
                    .checked_mul(MATCH_WORK)
                    .and_then(|matches| value.checked_add(matches))
            })
            .and_then(|value| value.checked_add(FIXED_REDUCE_WORK))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "generalized search work",
            })?;
        Ok(ReduceUpperBounds {
            input_bytes,
            source_reads,
            finder_scanned_bytes,
            finder_calls: anchor_candidates,
            anchor_candidates,
            classifications,
            literal_comparisons,
            work,
            run_events: anchor_candidates,
            candidate_events: anchor_candidates,
            match_events: anchor_candidates,
            count: u64::try_from(anchor_candidates).unwrap_or(u64::MAX),
            span_sum: u64::try_from(input_bytes).unwrap_or(u64::MAX),
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.peak_bytes,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the prefix search keeps metered anchor, shortest, greedy-run, suffix, and overlap progress in one auditable loop"
    )]
    fn search_prefix(
        &self,
        haystack: &[u8],
        projection: SearchProjection,
        upper: ReduceUpperBounds,
        meter: SearchMeter,
    ) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
        debug_assert_eq!(self.anchor_kind, Anchor::Prefix);
        let mut actual = new_search_actual();
        let mut cursor = 0_usize;
        loop {
            let Some((anchor_start, anchor_end)) =
                self.next_anchor(haystack, cursor, haystack.len(), &mut actual, meter)?
            else {
                return finish_search(None, actual, upper);
            };
            if self.suffix().is_empty() && projection == SearchProjection::EarliestEnd {
                let end = match self.minimum {
                    SearchRunMinimum::Zero => Some(anchor_end),
                    SearchRunMinimum::One => {
                        if anchor_end < haystack.len()
                            && self.class.contains(search_read_classified(
                                haystack,
                                anchor_end,
                                &mut actual,
                                meter,
                            )?)
                        {
                            meter.ensure_work(&actual, RUN_WORK)?;
                            actual.runs = checked_add(actual.runs, 1, "generalized shortest run")?;
                            actual.work = checked_add(
                                actual.work,
                                RUN_WORK,
                                "generalized shortest run work",
                            )?;
                            Some(anchor_end.checked_add(1).ok_or(
                                ReduceError::ArithmeticOverflow {
                                    computation: "generalized shortest end",
                                },
                            )?)
                        } else {
                            None
                        }
                    }
                };
                if let Some(end) = end {
                    actual.candidates =
                        checked_add(actual.candidates, 1, "generalized shortest candidate")?;
                    let matched = (anchor_start, end);
                    record_search_match(matched, &mut actual, meter)?;
                    return finish_search(Some(matched), actual, upper);
                }
                cursor = anchor_start
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "generalized rejected shortest progress",
                    })?;
                continue;
            }

            let recovered = if self.unicode_all_non_ascii {
                search_scan_unicode_all_non_ascii_run_forward(
                    haystack,
                    self.class,
                    self.ascii_scanner.as_ref(),
                    anchor_end,
                    &mut actual,
                    meter,
                )?
            } else {
                search_scan_class_run_forward(
                    haystack,
                    self.class,
                    self.ascii_scanner.as_ref(),
                    anchor_end,
                    &mut actual,
                    meter,
                )?
            };
            if recovered.is_some() {
                meter.ensure_work(&actual, RUN_WORK)?;
                actual.runs = checked_add(actual.runs, 1, "generalized run count")?;
                actual.work = checked_add(actual.work, RUN_WORK, "generalized run work")?;
            }
            let run_end = match (self.minimum, recovered) {
                (SearchRunMinimum::Zero, None) => anchor_end,
                (SearchRunMinimum::Zero | SearchRunMinimum::One, Some(end)) => end,
                (SearchRunMinimum::One, None) => {
                    cursor =
                        anchor_start
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "generalized missing-run progress",
                            })?;
                    continue;
                }
            };
            if self.suffix().is_empty() {
                actual.candidates =
                    checked_add(actual.candidates, 1, "generalized prefix-only candidate")?;
                let matched = (anchor_start, run_end);
                record_search_match(matched, &mut actual, meter)?;
                return finish_search(Some(matched), actual, upper);
            }

            let end = run_end.checked_add(self.suffix().len()).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "generalized candidate end",
                },
            )?;
            if end <= haystack.len() {
                actual.candidates =
                    checked_add(actual.candidates, 1, "generalized candidate count")?;
                if search_literal_equals(haystack, run_end, self.suffix(), &mut actual, meter)? {
                    let matched = (anchor_start, end);
                    record_search_match(matched, &mut actual, meter)?;
                    return finish_search(Some(matched), actual, upper);
                }
            }

            let overlapping_end = run_end
                .checked_sub(self.prefix().len())
                .and_then(|value| value.checked_add(1))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "generalized shared-run restart",
                })?;
            cursor = anchor_start
                .checked_add(1)
                .map(|next| next.max(overlapping_end))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "generalized rejected candidate progress",
                })?;
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the admitted fast path keeps every cursor within one proven nonempty-prefix slice"
    )]
    fn search_prefix_exists_value(&self, haystack: &[u8]) -> bool {
        debug_assert_eq!(self.anchor_kind, Anchor::Prefix);
        let prefix_bytes = self.prefix().len();
        let mut cursor = 0_usize;
        loop {
            let Some(relative) = self.anchor.find(&haystack[cursor..]) else {
                return false;
            };
            let anchor_start = cursor + relative;
            let anchor_end = anchor_start + prefix_bytes;

            if self.suffix().is_empty() {
                match self.minimum {
                    SearchRunMinimum::Zero => return true,
                    SearchRunMinimum::One => {
                        if anchor_end < haystack.len() && self.class.contains(haystack[anchor_end])
                        {
                            return true;
                        }
                        cursor = anchor_start + 1;
                        continue;
                    }
                }
            }

            let recovered = if self.unicode_all_non_ascii {
                scan_unicode_all_non_ascii_run_forward_value(
                    haystack,
                    self.class,
                    self.ascii_scanner.as_ref(),
                    anchor_end,
                )
            } else {
                scan_class_run_forward_value(
                    haystack,
                    self.class,
                    self.ascii_scanner.as_ref(),
                    anchor_end,
                )
            };
            let run_end = match (self.minimum, recovered) {
                (SearchRunMinimum::Zero, None) => anchor_end,
                (SearchRunMinimum::Zero | SearchRunMinimum::One, Some(end)) => end,
                (SearchRunMinimum::One, None) => {
                    cursor = anchor_start + 1;
                    continue;
                }
            };
            if haystack
                .get(run_end..)
                .is_some_and(|remaining| remaining.starts_with(self.suffix()))
            {
                return true;
            }

            // Prefix occurrences whose repeated runs share an end can be
            // skipped as a group. These additions are bounded by the slice:
            // the prefix is nonempty, the anchor lies inside the slice, and
            // the recovered run end never exceeds it.
            let overlapping_end = run_end - prefix_bytes + 1;
            cursor = (anchor_start + 1).max(overlapping_end);
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the admitted fast path keeps every cursor within one proven nonempty-prefix slice"
    )]
    fn search_prefix_selected_value(&self, haystack: &[u8]) -> Option<(usize, usize)> {
        debug_assert_eq!(self.anchor_kind, Anchor::Prefix);
        let prefix_bytes = self.prefix().len();
        let mut cursor = 0_usize;
        loop {
            let relative = self.anchor.find(&haystack[cursor..])?;
            let anchor_start = cursor + relative;
            let anchor_end = anchor_start + prefix_bytes;
            let recovered = if self.unicode_all_non_ascii {
                scan_unicode_all_non_ascii_run_forward_value(
                    haystack,
                    self.class,
                    self.ascii_scanner.as_ref(),
                    anchor_end,
                )
            } else {
                scan_class_run_forward_value(
                    haystack,
                    self.class,
                    self.ascii_scanner.as_ref(),
                    anchor_end,
                )
            };
            let run_end = match (self.minimum, recovered) {
                (SearchRunMinimum::Zero, None) => anchor_end,
                (SearchRunMinimum::Zero | SearchRunMinimum::One, Some(end)) => end,
                (SearchRunMinimum::One, None) => {
                    cursor = anchor_start + 1;
                    continue;
                }
            };
            if self.suffix().is_empty() {
                return Some((anchor_start, run_end));
            }
            if haystack
                .get(run_end..)
                .is_some_and(|remaining| remaining.starts_with(self.suffix()))
            {
                return Some((anchor_start, run_end + self.suffix().len()));
            }

            // Prefix occurrences whose repeated runs share one end can be
            // skipped as a group. These additions are bounded by the slice:
            // the prefix is nonempty, the anchor lies inside the slice, and
            // the recovered run end never exceeds it.
            let overlapping_end = run_end - prefix_bytes + 1;
            cursor = (anchor_start + 1).max(overlapping_end);
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the nonempty suffix finder bounds every full-haystack offset and rejected overlap restart"
    )]
    fn search_ascii_word_suffix_selected_value(
        &self,
        haystack: &[u8],
    ) -> Option<(usize, usize)> {
        debug_assert_eq!(self.anchor_kind, Anchor::CompleteAsciiWordSuffix);
        let suffix_bytes = self.anchor.needle().len();
        debug_assert!(suffix_bytes != 0);
        let mut cursor = 0_usize;
        loop {
            let relative = self.anchor.find(&haystack[cursor..])?;
            let suffix_start = cursor + relative;
            let suffix_end = suffix_start + suffix_bytes;
            if haystack
                .get(suffix_end)
                .is_some_and(|&byte| is_ascii_word(byte))
            {
                cursor = suffix_start + 1;
                continue;
            }

            let Some(run_start) = scan_class_run_backward_value(
                haystack,
                self.class,
                self.ascii_scanner.as_ref(),
                suffix_start,
            )
            .filter(|&start| start < suffix_start) else {
                cursor = suffix_start + 1;
                continue;
            };
            if run_start > 0 && is_ascii_word(haystack[run_start - 1]) {
                cursor = suffix_start + 1;
                continue;
            }
            return Some((run_start, suffix_end));
        }
    }

    fn search_ascii_word_suffix(
        &self,
        original: &[u8],
        haystack: &[u8],
        window_start: usize,
        upper: ReduceUpperBounds,
        meter: SearchMeter,
    ) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
        debug_assert_eq!(self.anchor_kind, Anchor::CompleteAsciiWordSuffix);
        let mut actual = new_search_actual();
        let mut cursor = 0_usize;
        loop {
            let Some((suffix_start, suffix_end)) =
                self.next_anchor(haystack, cursor, haystack.len(), &mut actual, meter)?
            else {
                return finish_search(None, actual, upper);
            };
            let absolute_suffix_end =
                window_start
                    .checked_add(suffix_end)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "absolute generalized guarded suffix end",
                    })?;
            if absolute_suffix_end < original.len()
                && is_ascii_word(search_read_classified(
                    original,
                    absolute_suffix_end,
                    &mut actual,
                    meter,
                )?)
            {
                cursor = suffix_start
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "generalized embedded suffix progress",
                    })?;
                continue;
            }

            actual.candidates = checked_add(actual.candidates, 1, "generalized guarded candidate")?;
            let Some(run_start) = search_scan_class_run_backward(
                haystack,
                self.class,
                self.ascii_scanner.as_ref(),
                suffix_start,
                &mut actual,
                meter,
            )?
            .filter(|&start| start < suffix_start) else {
                cursor = suffix_start
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "generalized missing guarded run progress",
                    })?;
                continue;
            };
            meter.ensure_work(&actual, RUN_WORK)?;
            actual.runs = checked_add(actual.runs, 1, "generalized guarded run")?;
            actual.work = checked_add(actual.work, RUN_WORK, "generalized guarded run work")?;
            let absolute_run_start =
                window_start
                    .checked_add(run_start)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "absolute generalized guarded run start",
                    })?;
            if absolute_run_start > 0 {
                let previous =
                    absolute_run_start
                        .checked_sub(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "generalized guarded predecessor",
                        })?;
                if is_ascii_word(search_read_classified(
                    original,
                    previous,
                    &mut actual,
                    meter,
                )?) {
                    cursor =
                        suffix_start
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "generalized left-boundary rejection progress",
                            })?;
                    continue;
                }
            }
            let matched = (run_start, suffix_end);
            record_search_match(matched, &mut actual, meter)?;
            return finish_search(Some(matched), actual, upper);
        }
    }

    fn next_anchor(
        &self,
        haystack: &[u8],
        cursor: usize,
        end: usize,
        actual: &mut ReduceActualCounters,
        meter: SearchMeter,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let anchor_bytes = self.anchor.needle().len();
        let remaining = end
            .checked_sub(cursor)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "generalized anchor remaining bytes",
            })?;
        if remaining < anchor_bytes {
            return Ok(None);
        }
        meter.ensure_work(actual, FINDER_CALL_WORK)?;
        actual.finder_calls = checked_add(actual.finder_calls, 1, "generalized finder calls")?;
        actual.work = checked_add(
            actual.work,
            FINDER_CALL_WORK,
            "generalized finder call work",
        )?;
        let service_bytes = if meter.work_envelope_admitted {
            remaining
        } else {
            meter.service_capacity(actual, FINDER_SCAN_WORK)?
        };
        if service_bytes < anchor_bytes {
            let required = anchor_bytes.checked_mul(FINDER_SCAN_WORK).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "metered generalized anchor minimum service work",
                },
            )?;
            meter.ensure_work(actual, required)?;
            return Err(SearchError::Kernel(ReduceError::AccountingInvariant {
                resource: "metered generalized anchor minimum service",
                actual: 1,
                upper: 0,
            }));
        }
        let search_end = cursor.saturating_add(service_bytes).min(end);
        let search = haystack
            .get(cursor..search_end)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "generalized anchor window",
            })?;
        let Some(relative) = self.anchor.find(search) else {
            charge_finder_scan(actual, search.len())?;
            if search_end != end {
                meter.ensure_work(actual, FINDER_SCAN_WORK)?;
                return Err(SearchError::Kernel(ReduceError::AccountingInvariant {
                    resource: "metered generalized anchor continuation",
                    actual: 1,
                    upper: 0,
                }));
            }
            return Ok(None);
        };
        let finder_service =
            relative
                .checked_add(anchor_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "generalized successful finder service",
                })?;
        charge_finder_scan(actual, finder_service)?;
        let start = cursor
            .checked_add(relative)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "generalized anchor start",
            })?;
        let anchor_end =
            start
                .checked_add(anchor_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "generalized anchor end",
                })?;
        meter.ensure_anchor_candidate(actual)?;
        meter.ensure_work(actual, ANCHOR_CANDIDATE_WORK)?;
        actual.anchor_candidates =
            checked_add(actual.anchor_candidates, 1, "generalized anchor candidates")?;
        actual.work = checked_add(
            actual.work,
            ANCHOR_CANDIDATE_WORK,
            "generalized anchor candidate work",
        )?;
        Ok(Some((start, anchor_end)))
    }
}

impl BoundedLiteralClassRunPlan {
    pub fn build<I>(
        prefix: &[u8],
        ranges: I,
        suffix: &[u8],
        minimum: usize,
        maximum: usize,
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_inner(
            None,
            prefix,
            ranges,
            suffix,
            minimum,
            maximum,
            limits,
            BoundedNativeAdmission::Unconditional,
        )
        .map(|plan| plan.expect("unconditional finite build cannot decline admission"))
    }

    pub fn build_with_dispatch<I>(
        dispatch: SimdDispatchContext,
        prefix: &[u8],
        ranges: I,
        suffix: &[u8],
        minimum: usize,
        maximum: usize,
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_inner(
            Some((dispatch, DispatchPolicy::Auto)),
            prefix,
            ranges,
            suffix,
            minimum,
            maximum,
            limits,
            BoundedNativeAdmission::Unconditional,
        )
        .map(|plan| plan.expect("unconditional finite build cannot decline admission"))
    }

    /// Build this finite direct plan only when its immutable structure proves
    /// a native advantage over the generic forward K0 fallback.
    ///
    /// A semantic decline is returned as `Ok(None)` before either literal or
    /// Finder is allocated. Resource failures remain ordinary build errors so
    /// callers cannot turn an exhausted construction budget into a fallback.
    pub fn build_with_dispatch_if_admitted<I>(
        dispatch: SimdDispatchContext,
        prefix: &[u8],
        ranges: I,
        suffix: &[u8],
        minimum: usize,
        maximum: usize,
        limits: BuildLimits,
    ) -> Result<Option<Self>, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_inner(
            Some((dispatch, DispatchPolicy::Auto)),
            prefix,
            ranges,
            suffix,
            minimum,
            maximum,
            limits,
            BoundedNativeAdmission::RequireCostProof,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the finite direct builder keeps exact-shape revalidation and every retained allocation charge adjacent"
    )]
    fn build_inner<I>(
        dispatch: Option<(SimdDispatchContext, DispatchPolicy)>,
        prefix: &[u8],
        mut ranges: I,
        suffix: &[u8],
        minimum: usize,
        maximum: usize,
        limits: BuildLimits,
        admission: BoundedNativeAdmission,
    ) -> Result<Option<Self>, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        if prefix.is_empty() {
            return Err(BuildError::EmptyPrefix);
        }
        if suffix.is_empty() {
            return Err(BuildError::EmptySuffix);
        }
        if minimum > maximum {
            return Err(BuildError::InvalidFiniteBounds { minimum, maximum });
        }
        let literal_bytes = prefix
            .len()
            .checked_add(suffix.len())
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "finite literal byte total",
            })?;
        enforce_build(
            literal_bytes,
            limits.max_literal_bytes,
            BuildResource::LiteralBytes,
        )?;
        let persistent_bytes = size_of::<Self>()
            .checked_add(literal_bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "finite direct persistent bytes",
            })?;
        enforce_build(
            persistent_bytes,
            limits.max_persistent_bytes,
            BuildResource::Persistent,
        )?;
        enforce_build(persistent_bytes, limits.max_peak_bytes, BuildResource::Peak)?;
        enforce_build(0, limits.max_scratch_bytes, BuildResource::Scratch)?;

        let mut actual = DirectBuildAttemptActual::default();
        let (
            class,
            class_ranges,
            class_members,
            ascii_scanner,
            preferred_anchor,
            work_upper_bound,
        ) = {
            let mut work = BuildWork::new(limits.max_build_work, &mut actual);
            work.charge(size_of::<Self>())?;
            work.charge(
                literal_bytes
                    .checked_mul(LITERAL_BUILD_WORK_PER_BYTE)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "finite literal copy work",
                    })?,
            )?;
            work.charge(
                literal_bytes
                    .checked_mul(BOUNDED_FINDER_BUILD_WORK_PER_BYTE)
                    .and_then(|finder| {
                        BOUNDED_FINDER_BUILD_FIXED_WORK
                            .checked_mul(2)
                            .and_then(|fixed| finder.checked_add(fixed))
                    })
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "finite finder build work",
                    })?,
            )?;
            let (class, class_ranges, class_members) =
                build_class(&mut ranges, limits, &mut work)?;
            work.charge(1)?;
            if class.contains(*prefix.last().expect("nonempty prefix was checked")) {
                return Err(BuildError::PrefixBoundaryInClass);
            }
            work.charge(1)?;
            if class.contains(suffix[0]) {
                return Err(BuildError::SuffixBoundaryInClass);
            }
            work.charge(
                ANCHOR_SELECTION_WORK
                    .checked_add(2)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "finite anchor and bound selection work",
                    })?,
            )?;
            let score_mode = match admission {
                BoundedNativeAdmission::Unconditional => {
                    BoundedAnchorScoreMode::LazyPreference
                }
                BoundedNativeAdmission::RequireCostProof => {
                    BoundedAnchorScoreMode::AdmissionProof
                }
            };
            let selection = bounded_anchor_selection(prefix, suffix, &mut work, score_mode)?;
            let ascii_scanner = build_ascii_scanner(
                dispatch.filter(|_| class.is_ascii()),
                class,
                false,
                &mut work,
            )?;
            if admission == BoundedNativeAdmission::RequireCostProof {
                work.charge(BOUNDED_NATIVE_ADMISSION_WORK)?;
                if !bounded_native_cost_admitted(
                    maximum,
                    selection,
                    bounded_ascii_scanner_has_vector(ascii_scanner.as_ref()),
                )? {
                    return Ok(None);
                }
            }
            (
                class,
                class_ranges,
                class_members,
                ascii_scanner,
                selection.preferred,
                work.used,
            )
        };

        let prefix = copy_literal(prefix, "finite direct prefix")?;
        let prefix_bytes = prefix.len();
        record_literal_copy(&mut actual, prefix_bytes)?;
        let suffix = copy_literal(suffix, "finite direct suffix")?;
        let suffix_bytes = suffix.len();
        record_literal_copy(&mut actual, suffix_bytes)?;
        Ok(Some(Self {
            prefix: FinderBuilder::new().build_forward_owned(prefix),
            suffix: FinderBuilder::new().build_forward_owned(suffix),
            class,
            ascii_scanner,
            minimum,
            maximum,
            preferred_anchor,
            build: BuildAccounting {
                prefix_bytes,
                suffix_bytes,
                literal_bytes,
                class_ranges,
                class_members,
                work_upper_bound,
                scratch_bytes: 0,
                persistent_bytes,
                peak_bytes: persistent_bytes,
            },
        }))
    }

    #[must_use]
    pub const fn plan_id(&self) -> &'static str {
        BOUNDED_SEARCH_PLAN_ID
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    #[must_use]
    pub const fn minimum(&self) -> usize {
        self.minimum
    }

    #[must_use]
    pub const fn maximum(&self) -> usize {
        self.maximum
    }

    fn prefix(&self) -> &[u8] {
        self.prefix.needle()
    }

    fn suffix(&self) -> &[u8] {
        self.suffix.needle()
    }

    fn bounded_scan_bytes(&self, remaining: usize) -> usize {
        remaining.min(self.maximum.checked_add(1).unwrap_or(remaining))
    }

    const fn bounded_scan_classification_overhead(&self) -> usize {
        match self.ascii_scanner {
            Some(AsciiClassScanner::Run(scanner)) => scanner.max_classification_overhead(),
            Some(AsciiClassScanner::Fixed(_)) => ASCII_WIDE_BYTES - 1,
            None => 0,
        }
    }

    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.find_window(haystack, Window::full(haystack), limits)
    }

    pub fn find_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.search_window(haystack, window, limits, SearchProjection::Selected)
    }

    pub fn shortest_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        let (matched, accounting) =
            self.search_window(haystack, window, limits, SearchProjection::EarliestEnd)?;
        Ok((matched.map(|(_, end)| end), accounting))
    }

    pub fn shortest_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<Option<usize>, SearchError> {
        let (upper, _, meter) =
            self.search_preflight(haystack.len(), window, limits, self.preferred_anchor)?;
        if !meter.work_envelope_admitted
            || upper.anchor_candidates > limits.max_candidate_visits
        {
            return self
                .shortest_window(haystack, window, limits)
                .map(|(matched, _)| matched);
        }
        let slice = &haystack[window.start()..window.end()];
        let matched = match self.preferred_anchor {
            Anchor::Prefix => self.find_prefix_value(slice),
            Anchor::Suffix => self.find_suffix_value(slice),
            Anchor::CompleteAsciiWordSuffix => unreachable!("finite direct anchor is unguarded"),
        };
        matched
            .map(|(_, end)| {
                window
                    .start()
                    .checked_add(end)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "absolute finite value shortest end",
                    })
            })
            .transpose()
            .map_err(SearchError::from)
    }

    pub fn is_match_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        let (matched, accounting) = self.search_anchor_window(
            haystack,
            window,
            limits,
            BOUNDED_EXISTS_SEARCH_OPERATION_ID,
        )?;
        Ok((matched.is_some(), accounting))
    }

    pub fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        let (upper, _, meter) =
            self.search_preflight(haystack.len(), window, limits, self.preferred_anchor)?;
        if !meter.work_envelope_admitted
            || upper.anchor_candidates > limits.max_candidate_visits
        {
            return self
                .is_match_window(haystack, window, limits)
                .map(|(matched, _)| matched);
        }
        let slice = &haystack[window.start()..window.end()];
        Ok(match self.preferred_anchor {
            Anchor::Prefix => self.find_prefix_value(slice).is_some(),
            Anchor::Suffix => self.find_suffix_value(slice).is_some(),
            Anchor::CompleteAsciiWordSuffix => unreachable!("finite direct anchor is unguarded"),
        })
    }

    pub fn find_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let (upper, _, meter) =
            self.search_preflight(haystack.len(), window, limits, self.preferred_anchor)?;
        if !meter.work_envelope_admitted
            || upper.anchor_candidates > limits.max_candidate_visits
        {
            return self
                .find_window(haystack, window, limits)
                .map(|(matched, _)| matched);
        }
        let slice = &haystack[window.start()..window.end()];
        let matched = match self.preferred_anchor {
            Anchor::Prefix => self.find_prefix_value(slice),
            Anchor::Suffix => self.find_suffix_value(slice),
            Anchor::CompleteAsciiWordSuffix => unreachable!("finite direct anchor is unguarded"),
        };
        matched
            .map(|(start, end)| {
                Ok::<(usize, usize), ReduceError>((
                    window.start().checked_add(start).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "absolute finite value match start",
                        },
                    )?,
                    window.start().checked_add(end).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "absolute finite value match end",
                        },
                    )?,
                ))
            })
            .transpose()
            .map_err(SearchError::from)
    }

    fn search_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
        projection: SearchProjection,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        let operation_id = match projection {
            SearchProjection::Selected => BOUNDED_SEARCH_OPERATION_ID,
            SearchProjection::EarliestEnd => BOUNDED_SHORTEST_SEARCH_OPERATION_ID,
        };
        self.search_anchor_window(haystack, window, limits, operation_id)
    }

    fn search_anchor_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
        operation_id: &'static str,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        let anchor = self.preferred_anchor;
        let (upper, window_bytes, meter) =
            self.search_preflight(haystack.len(), window, limits, anchor)?;
        let slice = &haystack[window.start()..window.end()];
        let (matched, actual) = match anchor {
            Anchor::Prefix => self.search_prefix(slice, upper, meter)?,
            Anchor::Suffix => self.search_suffix(slice, upper, meter)?,
            Anchor::CompleteAsciiWordSuffix => unreachable!("finite direct anchor is unguarded"),
        };
        let matched = matched
            .map(|(start, end)| {
                Ok::<(usize, usize), ReduceError>((
                    window.start().checked_add(start).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "absolute finite match start",
                        },
                    )?,
                    window.start().checked_add(end).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "absolute finite match end",
                        },
                    )?,
                ))
            })
            .transpose()?;
        Ok((
            matched,
            SearchAccounting {
                operation_id,
                window_bytes,
                assertion_context_bytes: 0,
                candidate_visits_upper_bound: upper.anchor_candidates,
                source_reads_upper_bound: upper.source_reads,
                work_upper_bound: u64::try_from(upper.work).unwrap_or(u64::MAX),
                scratch_bytes: 0,
                candidate_visits: actual.anchor_candidates,
                finder_calls: actual.finder_calls,
                classifications: actual.classifications,
                literal_comparisons: actual.literal_comparisons,
                source_reads: actual.source_reads,
                work: actual.work,
            },
        ))
    }

    fn search_preflight(
        &self,
        haystack_len: usize,
        window: Window,
        limits: SearchLimits,
        anchor: Anchor,
    ) -> Result<(ReduceUpperBounds, usize, SearchMeter), SearchError> {
        if window.start() > window.end() || window.end() > haystack_len {
            return Err(SearchError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len,
            });
        }
        let window_bytes =
            window
                .end()
                .checked_sub(window.start())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "finite search window bytes",
                })?;
        let upper = self.search_upper_bounds(window_bytes, anchor)?;
        let meter = SearchMeter::new(upper, limits)?;
        Ok((upper, window_bytes, meter))
    }

    fn search_upper_bounds(
        &self,
        input_bytes: usize,
        anchor: Anchor,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let (anchor_bytes, opposite_bytes) = match anchor {
            Anchor::Prefix => (self.prefix().len(), self.suffix().len()),
            Anchor::Suffix => (self.suffix().len(), self.prefix().len()),
            Anchor::CompleteAsciiWordSuffix => unreachable!("finite direct anchor is unguarded"),
        };
        let candidates = input_bytes
            .checked_sub(anchor_bytes)
            .and_then(|remaining| remaining.checked_add(1))
            .unwrap_or(0);
        let finder_scanned_bytes = candidates
            .checked_mul(anchor_bytes.saturating_sub(1))
            .and_then(|overlap| input_bytes.checked_add(overlap))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "finite overlapping finder service",
            })?;
        let classification_overhead = self.bounded_scan_classification_overhead();
        let global_classifications = candidates
            .checked_mul(classification_overhead)
            .and_then(|overhead| {
                input_bytes
                    .checked_add(candidates)
                    .and_then(|logical| logical.checked_add(overhead))
            });
        // A run scanner can classify one failed vector block and then
        // classify part of that same block again during scalar boundary
        // recovery. Bound each supplied max+1 slice together with that
        // scanner-specific terminal overhead.
        let capped_classifications = self
            .bounded_scan_bytes(input_bytes)
            .checked_add(classification_overhead)
            .and_then(|per_candidate| candidates.checked_mul(per_candidate));
        let classifications = match (global_classifications, capped_classifications) {
            (Some(global), Some(capped)) => global.min(capped),
            (Some(global), None) => global,
            (None, Some(capped)) => capped,
            (None, None) => {
                return Err(ReduceError::ArithmeticOverflow {
                    computation: "finite bounded class-run classifications",
                });
            }
        };
        let literal_comparisons = candidates.checked_mul(opposite_bytes).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "finite opposite literal comparisons",
            },
        )?;
        let source_reads = finder_scanned_bytes
            .checked_add(classifications)
            .and_then(|reads| reads.checked_add(literal_comparisons))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "finite direct source reads",
            })?;
        let work = finder_scanned_bytes
            .checked_mul(FINDER_SCAN_WORK)
            .and_then(|value| value.checked_add(candidates.checked_mul(FINDER_CALL_WORK)?))
            .and_then(|value| value.checked_add(candidates.checked_mul(ANCHOR_CANDIDATE_WORK)?))
            .and_then(|value| value.checked_add(classifications.checked_mul(CLASSIFICATION_WORK)?))
            .and_then(|value| {
                value.checked_add(literal_comparisons.checked_mul(LITERAL_COMPARISON_WORK)?)
            })
            .and_then(|value| value.checked_add(candidates.checked_mul(RUN_WORK)?))
            .and_then(|value| value.checked_add(candidates.checked_mul(MATCH_WORK)?))
            .and_then(|value| value.checked_add(FIXED_REDUCE_WORK))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "finite direct search work",
            })?;
        Ok(ReduceUpperBounds {
            input_bytes,
            source_reads,
            finder_scanned_bytes,
            finder_calls: candidates,
            anchor_candidates: candidates,
            classifications,
            literal_comparisons,
            work,
            run_events: candidates,
            candidate_events: candidates,
            match_events: candidates,
            count: u64::try_from(candidates).unwrap_or(u64::MAX),
            span_sum: u64::try_from(input_bytes).unwrap_or(u64::MAX),
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.peak_bytes,
        })
    }

    fn search_prefix(
        &self,
        haystack: &[u8],
        upper: ReduceUpperBounds,
        meter: SearchMeter,
    ) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
        // Prefix occurrences are enumerated by increasing start. The proved
        // outside-class suffix boundary prevents accepted spans from crossing,
        // so the first accepted prefix also has the earliest accepting end.
        let mut actual = new_search_actual();
        let mut cursor = 0;
        loop {
            let Some((start, prefix_end)) = self.next_anchor(
                &self.prefix,
                haystack,
                cursor,
                &mut actual,
                meter,
            )? else {
                return finish_search(None, actual, upper);
            };
            let scan_bytes = self.bounded_scan_bytes(haystack.len().saturating_sub(prefix_end));
            let scan_end = prefix_end.checked_add(scan_bytes).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "finite forward bounded scan end",
                },
            )?;
            let scan_haystack = haystack.get(..scan_end).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "finite forward bounded scan window",
                },
            )?;
            let run_end = search_scan_class_run_forward(
                scan_haystack,
                self.class,
                self.ascii_scanner.as_ref(),
                prefix_end,
                &mut actual,
                meter,
            )?
            .unwrap_or(prefix_end);
            let run_len = run_end.checked_sub(prefix_end).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "finite forward run length",
                },
            )?;
            if run_len != 0 {
                meter.ensure_work(&actual, RUN_WORK)?;
                actual.runs = checked_add(actual.runs, 1, "finite forward run")?;
                actual.work = checked_add(actual.work, RUN_WORK, "finite forward run work")?;
            }
            if run_len >= self.minimum && run_len <= self.maximum {
                let end = run_end.checked_add(self.suffix().len()).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "finite selected end",
                    },
                )?;
                if end <= haystack.len() {
                    actual.candidates = checked_add(actual.candidates, 1, "finite candidate")?;
                    if search_literal_equals(
                        haystack,
                        run_end,
                        self.suffix(),
                        &mut actual,
                        meter,
                    )? {
                        let matched = (start, end);
                        record_search_match(matched, &mut actual, meter)?;
                        return finish_search(Some(matched), actual, upper);
                    }
                }
            }
            cursor = start.checked_add(1).ok_or(ReduceError::ArithmeticOverflow {
                computation: "finite prefix progress",
            })?;
        }
    }

    fn search_suffix(
        &self,
        haystack: &[u8],
        upper: ReduceUpperBounds,
        meter: SearchMeter,
    ) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
        // Fixed-width suffix occurrences are enumerated by increasing end.
        // The proved outside-class prefix boundary prevents accepted spans
        // from crossing, so the first accepted suffix also has the selected
        // start.
        let mut actual = new_search_actual();
        let mut cursor = 0;
        loop {
            let Some((suffix_start, end)) = self.next_anchor(
                &self.suffix,
                haystack,
                cursor,
                &mut actual,
                meter,
            )? else {
                return finish_search(None, actual, upper);
            };
            let scan_bytes = self.bounded_scan_bytes(suffix_start);
            let scan_floor = suffix_start.checked_sub(scan_bytes).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "finite backward bounded scan floor",
                },
            )?;
            let scan_haystack = haystack.get(scan_floor..).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "finite backward bounded scan window",
                },
            )?;
            let relative_run_start = search_scan_class_run_backward(
                scan_haystack,
                self.class,
                self.ascii_scanner.as_ref(),
                scan_bytes,
                &mut actual,
                meter,
            )?
            .unwrap_or(scan_bytes);
            let run_start = scan_floor.checked_add(relative_run_start).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "finite absolute backward run start",
                },
            )?;
            let run_len = suffix_start.checked_sub(run_start).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "finite backward run length",
                },
            )?;
            if run_len != 0 {
                meter.ensure_work(&actual, RUN_WORK)?;
                actual.runs = checked_add(actual.runs, 1, "finite backward run")?;
                actual.work = checked_add(actual.work, RUN_WORK, "finite backward run work")?;
            }
            if run_len >= self.minimum && run_len <= self.maximum {
                if let Some(start) = run_start.checked_sub(self.prefix().len()) {
                    actual.candidates = checked_add(actual.candidates, 1, "finite candidate")?;
                    if search_literal_equals(
                        haystack,
                        start,
                        self.prefix(),
                        &mut actual,
                        meter,
                    )? {
                        let matched = (start, end);
                        record_search_match(matched, &mut actual, meter)?;
                        return finish_search(Some(matched), actual, upper);
                    }
                }
            }
            cursor = suffix_start.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "finite suffix progress",
                },
            )?;
        }
    }

    fn next_anchor(
        &self,
        finder: &Finder<'static>,
        haystack: &[u8],
        cursor: usize,
        actual: &mut ReduceActualCounters,
        meter: SearchMeter,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let anchor_bytes = finder.needle().len();
        let remaining = haystack.len().checked_sub(cursor).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "finite anchor remaining bytes",
            },
        )?;
        if remaining < anchor_bytes {
            return Ok(None);
        }
        meter.ensure_work(actual, FINDER_CALL_WORK)?;
        actual.finder_calls = checked_add(actual.finder_calls, 1, "finite finder calls")?;
        actual.work = checked_add(actual.work, FINDER_CALL_WORK, "finite finder call work")?;
        let service_bytes = if meter.work_envelope_admitted {
            remaining
        } else {
            meter.service_capacity(actual, FINDER_SCAN_WORK)?
        };
        if service_bytes < anchor_bytes {
            let required = anchor_bytes.checked_mul(FINDER_SCAN_WORK).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "finite minimum finder service",
                },
            )?;
            meter.ensure_work(actual, required)?;
            return Err(SearchError::Kernel(ReduceError::AccountingInvariant {
                resource: "metered finite anchor minimum service",
                actual: 1,
                upper: 0,
            }));
        }
        let search_end = cursor.saturating_add(service_bytes).min(haystack.len());
        let search = &haystack[cursor..search_end];
        let Some(relative) = finder.find(search) else {
            charge_finder_scan(actual, search.len())?;
            if search_end != haystack.len() {
                meter.ensure_work(actual, FINDER_SCAN_WORK)?;
                return Err(SearchError::Kernel(ReduceError::AccountingInvariant {
                    resource: "metered finite anchor continuation",
                    actual: 1,
                    upper: 0,
                }));
            }
            return Ok(None);
        };
        let finder_service = relative.checked_add(anchor_bytes).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "finite successful finder service",
            },
        )?;
        charge_finder_scan(actual, finder_service)?;
        let start = cursor.checked_add(relative).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "finite anchor start",
            },
        )?;
        let end = start.checked_add(anchor_bytes).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "finite anchor end",
            },
        )?;
        meter.ensure_anchor_candidate(actual)?;
        meter.ensure_work(actual, ANCHOR_CANDIDATE_WORK)?;
        actual.anchor_candidates =
            checked_add(actual.anchor_candidates, 1, "finite anchor candidates")?;
        actual.work = checked_add(
            actual.work,
            ANCHOR_CANDIDATE_WORK,
            "finite anchor candidate work",
        )?;
        Ok(Some((start, end)))
    }

    fn find_prefix_value(&self, haystack: &[u8]) -> Option<(usize, usize)> {
        let mut cursor = 0;
        while cursor <= haystack.len() {
            let relative = self.prefix.find(haystack.get(cursor..)?)?;
            let start = cursor.checked_add(relative)?;
            let prefix_end = start.checked_add(self.prefix().len())?;
            let scan_bytes = self.bounded_scan_bytes(haystack.len().checked_sub(prefix_end)?);
            let scan_end = prefix_end.checked_add(scan_bytes)?;
            let run_end = scan_class_run_forward_value(
                haystack.get(..scan_end)?,
                self.class,
                self.ascii_scanner.as_ref(),
                prefix_end,
            )
            .unwrap_or(prefix_end);
            let run_len = run_end.checked_sub(prefix_end)?;
            if run_len >= self.minimum
                && run_len <= self.maximum
                && haystack
                    .get(run_end..)
                    .is_some_and(|remaining| remaining.starts_with(self.suffix()))
            {
                return run_end
                    .checked_add(self.suffix().len())
                    .map(|end| (start, end));
            }
            cursor = start.checked_add(1)?;
        }
        None
    }

    fn find_suffix_value(&self, haystack: &[u8]) -> Option<(usize, usize)> {
        let mut cursor = 0;
        while cursor <= haystack.len() {
            let relative = self.suffix.find(haystack.get(cursor..)?)?;
            let suffix_start = cursor.checked_add(relative)?;
            let end = suffix_start.checked_add(self.suffix().len())?;
            let scan_bytes = self.bounded_scan_bytes(suffix_start);
            let scan_floor = suffix_start.checked_sub(scan_bytes)?;
            let relative_run_start = scan_class_run_backward_value(
                haystack.get(scan_floor..)?,
                self.class,
                self.ascii_scanner.as_ref(),
                scan_bytes,
            )
            .unwrap_or(scan_bytes);
            let run_start = scan_floor.checked_add(relative_run_start)?;
            let run_len = suffix_start.checked_sub(run_start)?;
            if run_len >= self.minimum && run_len <= self.maximum {
                let start = run_start.checked_sub(self.prefix().len());
                if start.is_some_and(|start| {
                    haystack
                        .get(start..run_start)
                        .is_some_and(|actual| actual == self.prefix())
                }) {
                    return start.map(|start| (start, end));
                }
            }
            cursor = suffix_start.checked_add(1)?;
        }
        None
    }
}

#[cfg(test)]
fn bounded_preferred_anchor(
    prefix: &[u8],
    suffix: &[u8],
    work: &mut BuildWork<'_>,
) -> Result<Anchor, BuildError> {
    bounded_anchor_selection(
        prefix,
        suffix,
        work,
        BoundedAnchorScoreMode::LazyPreference,
    )
    .map(|selection| selection.preferred)
}

fn bounded_anchor_selection(
    prefix: &[u8],
    suffix: &[u8],
    work: &mut BuildWork<'_>,
    mode: BoundedAnchorScoreMode,
) -> Result<BoundedAnchorSelection, BuildError> {
    let prefix_frequency = bounded_anchor_frequency_score(prefix, work)?;
    let suffix_frequency = bounded_anchor_frequency_score(suffix, work)?;
    let frequency_order = suffix_frequency.cmp(&prefix_frequency);
    let sampled_repetition = if frequency_order == core::cmp::Ordering::Equal
        || mode == BoundedAnchorScoreMode::AdmissionProof
    {
        bounded_repetition_preference(prefix, suffix, work)?
    } else {
        None
    };
    let preferred = match frequency_order {
        core::cmp::Ordering::Less => Anchor::Suffix,
        core::cmp::Ordering::Greater => Anchor::Prefix,
        core::cmp::Ordering::Equal => match sampled_repetition {
            Some(preference) => preference.preferred,
            None => {
                work.charge(1)?;
                if suffix.len() >= prefix.len() {
                    Anchor::Suffix
                } else {
                    Anchor::Prefix
                }
            }
        },
    };
    let strict_full_width = if prefix.len() <= usize::from(u8::MAX)
        && suffix.len() <= usize::from(u8::MAX)
    {
        sampled_repetition
    } else {
        None
    };
    Ok(BoundedAnchorSelection {
        preferred,
        strict_full_width_repetition: strict_full_width.map(|proof| proof.preferred),
        strict_full_width_opposite_period: strict_full_width
            .map(|proof| proof.opposite_primitive_period),
    })
}

fn bounded_repetition_preference(
    prefix: &[u8],
    suffix: &[u8],
    work: &mut BuildWork<'_>,
) -> Result<Option<BoundedRepetitionPreference>, BuildError> {
    let prefix_overlap = bounded_anchor_overlap_score(prefix, work)?;
    let suffix_overlap = bounded_anchor_overlap_score(suffix, work)?;
    work.charge(2)?;
    let prefix_factor = u128::try_from(prefix.len())
        .ok()
        .and_then(|width| {
            u128::try_from(suffix_overlap.primitive_period)
                .ok()
                .and_then(|period| width.checked_mul(period))
        })
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "finite prefix repetition factor cross-product",
        })?;
    let suffix_factor = u128::try_from(suffix.len())
        .ok()
        .and_then(|width| {
            u128::try_from(prefix_overlap.primitive_period)
                .ok()
                .and_then(|period| width.checked_mul(period))
        })
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "finite suffix repetition factor cross-product",
        })?;
    work.charge(1)?;
    match suffix_factor.cmp(&prefix_factor) {
        core::cmp::Ordering::Less => Ok(Some(BoundedRepetitionPreference {
            preferred: Anchor::Suffix,
            opposite_primitive_period: prefix_overlap.primitive_period,
        })),
        core::cmp::Ordering::Greater => Ok(Some(BoundedRepetitionPreference {
            preferred: Anchor::Prefix,
            opposite_primitive_period: suffix_overlap.primitive_period,
        })),
        core::cmp::Ordering::Equal => Ok(None),
    }
}

fn bounded_native_cost_admitted(
    maximum: usize,
    selection: BoundedAnchorSelection,
    has_vector_scanner: bool,
) -> Result<bool, BuildError> {
    // A strictly less repetitive chosen anchor is sufficient on its own,
    // except for a prefix-driven plan that must verify a uniform suffix.
    // That degenerate opposite literal creates the same dense one-byte
    // verification stream that K0's mandatory-prefix route already handles
    // more efficiently. Period-two and wider exact roots remain admitted.
    // Otherwise, require enough bounded-run service to amortize one sustained
    // wide scan, and retain only the suffix-driven direction. Prefix-driven
    // search competes with K0's mandatory-prefix machinery and loses that
    // comparison as the input grows even when the bounded class scan itself
    // is wide. A complete strict-period proof above remains sufficient in
    // either direction.
    if selection.strict_full_width_repetition == Some(selection.preferred)
        && selection.strict_full_width_opposite_period.is_some_and(|period| {
            selection.preferred != Anchor::Prefix || period >= 2
        })
    {
        return Ok(true);
    }
    if !has_vector_scanner {
        return Ok(false);
    }
    let horizon = maximum.checked_add(1).unwrap_or(usize::MAX);
    let sustained_scan = ASCII_WIDE_BYTES.checked_mul(2).ok_or(
        BuildError::ArithmeticOverflow {
            computation: "finite native sustained scan horizon",
        },
    )?;
    match selection.preferred {
        Anchor::Suffix => Ok(horizon >= sustained_scan),
        Anchor::Prefix => Ok(false),
        Anchor::CompleteAsciiWordSuffix => {
            unreachable!("finite direct anchor is unguarded")
        }
    }
}

fn bounded_ascii_scanner_has_vector(scanner: Option<&AsciiClassScanner>) -> bool {
    let vector = match scanner {
        Some(AsciiClassScanner::Fixed(classifier)) => classifier.selection().wide().vector,
        Some(AsciiClassScanner::Run(scanner)) => scanner.selection().vector,
        None => return false,
    };
    !matches!(vector, VectorKind::Scalar)
}

fn bounded_anchor_frequency_score(
    literal: &[u8],
    work: &mut BuildWork<'_>,
) -> Result<u16, BuildError> {
    if literal.is_empty() {
        return Err(BuildError::MissingLiteralAnchor);
    }
    let sample_len = literal.len().min(usize::from(u8::MAX));
    let sample = &literal[..sample_len];
    work.charge(1)?;
    let first_byte = sample[0];
    let first_rank = crate::packed_literal_anchor_frequency_rank(first_byte);
    if sample.len() == 1 {
        return Ok(u16::from(first_rank) * 2);
    }
    work.charge(1)?;
    let second_byte = sample[1];
    let mut rare1 = (first_byte, first_rank);
    let mut rare2 = (
        second_byte,
        crate::packed_literal_anchor_frequency_rank(second_byte),
    );
    if rare2.1 < rare1.1 {
        core::mem::swap(&mut rare1, &mut rare2);
    }
    for index in 2..sample.len() {
        work.charge(1)?;
        let byte = sample[index];
        let rank = crate::packed_literal_anchor_frequency_rank(byte);
        if rank < rare1.1 {
            rare2 = rare1;
            rare1 = (byte, rank);
        } else if byte != rare1.0 && rank < rare2.1 {
            rare2 = (byte, rank);
        }
    }
    Ok(u16::from(rare1.1) + u16::from(rare2.1))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BoundedAnchorOverlapScore {
    primitive_period: usize,
}

fn bounded_anchor_overlap_score(
    literal: &[u8],
    work: &mut BuildWork<'_>,
) -> Result<BoundedAnchorOverlapScore, BuildError> {
    // The finder-frequency model and the overlap proof intentionally inspect
    // the same immutable prefix. Bounding the sample keeps the no-allocation
    // border analysis independent of adversarial literal width.
    work.charge(1)?;
    let sample_len = literal.len().min(usize::from(u8::MAX));
    Ok(BoundedAnchorOverlapScore {
        primitive_period: bounded_sample_primitive_period(&literal[..sample_len], work)?,
    })
}

/// Returns the least shift that can overlap two occurrences of `sample`.
/// Every examined byte equality is charged. The sample is nonempty and at
/// most 255 bytes, so this exhaustive, allocation-free proof performs at most
/// 32,385 equality probes, independent of the retained literal width.
fn bounded_sample_primitive_period(
    sample: &[u8],
    work: &mut BuildWork<'_>,
) -> Result<usize, BuildError> {
    for period in 1..sample.len() {
        let mut is_period = true;
        for index in period..sample.len() {
            work.charge(1)?;
            if sample[index] != sample[index - period] {
                is_period = false;
                break;
            }
        }
        if is_period {
            return Ok(period);
        }
    }
    Ok(sample.len())
}

const fn new_search_actual() -> ReduceActualCounters {
    ReduceActualCounters {
        source_reads: 0,
        finder_scanned_bytes: 0,
        finder_calls: 0,
        anchor_candidates: 0,
        classifications: 0,
        literal_comparisons: 0,
        runs: 0,
        candidates: 0,
        matches: 0,
        count: 0,
        span_sum: 0,
        work: FIXED_REDUCE_WORK,
        scratch_bytes: 0,
    }
}

fn record_reduce_match<F>(
    actual: &mut ReduceActualCounters,
    operation: Operation,
    start: usize,
    end: usize,
    visitor: &mut F,
) -> Result<(), ReduceError>
where
    F: FnMut(CompleteSpan),
{
    actual.matches = checked_add(actual.matches, 1, "actual match count")?;
    actual.count = actual
        .count
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "actual count",
        })?;
    if matches!(operation, Operation::SpanSum | Operation::SpanVisit) {
        let width = end
            .checked_sub(start)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual match width",
            })?;
        actual.span_sum = actual
            .span_sum
            .checked_add(
                u64::try_from(width).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "actual match width as u64",
                })?,
            )
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual span sum",
            })?;
    }
    actual.work = checked_add(actual.work, MATCH_WORK, "actual match work")?;
    if operation == Operation::SpanVisit {
        visitor(CompleteSpan { start, end });
    }
    Ok(())
}

fn record_search_match(
    (start, end): (usize, usize),
    actual: &mut ReduceActualCounters,
    meter: SearchMeter,
) -> Result<(), SearchError> {
    let width = end
        .checked_sub(start)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "search match width",
        })?;
    meter.ensure_work(actual, MATCH_WORK)?;
    actual.matches = checked_add(actual.matches, 1, "search match count")?;
    actual.count = actual
        .count
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "search result count",
        })?;
    actual.span_sum = actual
        .span_sum
        .checked_add(
            u64::try_from(width).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "search match width as u64",
            })?,
        )
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "search result span sum",
        })?;
    actual.work = checked_add(actual.work, MATCH_WORK, "search match work")?;
    Ok(())
}

fn finish_search(
    matched: Option<(usize, usize)>,
    mut actual: ReduceActualCounters,
    upper: ReduceUpperBounds,
) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
    actual.source_reads = actual
        .finder_scanned_bytes
        .checked_add(actual.classifications)
        .and_then(|reads| reads.checked_add(actual.literal_comparisons))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "search source reads",
        })?;
    verify_actual(actual, upper)?;
    Ok((matched, actual))
}

#[allow(
    clippy::too_many_lines,
    reason = "the source-free preflight keeps every finder, class, literal, result, and resource bound adjacent"
)]
fn derive_reduce_upper_bounds(
    build: BuildAccounting,
    class_scan: ClassScanKind,
    suffix_inside_class: bool,
    input_bytes: usize,
    operation: Operation,
) -> Result<ReduceUpperBounds, ReduceError> {
    let anchor_bytes = build.prefix_bytes.max(build.suffix_bytes);
    let opposite_literal_bytes = build.prefix_bytes.min(build.suffix_bytes);
    let possible_anchor_starts = input_bytes
        .checked_sub(anchor_bytes)
        .and_then(|remaining| remaining.checked_add(1))
        .unwrap_or(0);
    let repeated_anchor_bytes = possible_anchor_starts
        .checked_mul(
            anchor_bytes
                .checked_sub(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "nonempty anchor overlap width",
                })?,
        )
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "overlapping anchor finder service",
        })?;
    let general_finder_scanned_bytes =
        input_bytes
            .checked_add(repeated_anchor_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "complete anchor finder service",
            })?;
    let general_run_events = input_bytes / 2 + input_bytes % 2;
    let (
        finder_calls,
        finder_scanned_bytes,
        anchor_candidates,
        run_events,
        logical_classifications,
        simd_run_recoveries,
    ) = if suffix_inside_class && operation == Operation::Count {
        // The contained-suffix Count route coalesces all suffix occurrences in
        // one maximal class run. Such runs need at least A source bytes and
        // distinct runs need a separating nonmember, so there are at most
        // ceil(N/(A+1)). Outer Finder windows are disjoint; at most one inner
        // overlapping search is needed per run and those windows are also
        // disjoint.
        let run_denominator =
            anchor_bytes
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "contained suffix run denominator",
                })?;
        let contained_runs = input_bytes / run_denominator
            + usize::from(!input_bytes.is_multiple_of(run_denominator));
        let finder_calls = contained_runs
            .checked_mul(2)
            .and_then(|calls| calls.checked_add(1))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "contained suffix finder call bound",
            })?;
        let finder_scanned_bytes =
            input_bytes
                .checked_mul(2)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "contained suffix finder service bound",
                })?;
        let anchor_candidates =
            contained_runs
                .checked_mul(2)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "contained suffix anchor candidate bound",
                })?;
        let logical_classifications = contained_runs
            .checked_mul(2)
            .and_then(|probes| input_bytes.checked_add(probes))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "contained suffix run plus boundary probes",
            })?;
        (
            finder_calls,
            finder_scanned_bytes,
            anchor_candidates,
            contained_runs,
            logical_classifications,
            contained_runs,
        )
    } else {
        let logical_classifications = input_bytes.checked_add(possible_anchor_starts).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "class run plus adjacent class probes",
            },
        )?;
        (
            possible_anchor_starts,
            general_finder_scanned_bytes,
            possible_anchor_starts,
            general_run_events,
            logical_classifications,
            possible_anchor_starts,
        )
    };
    let classifications = match class_scan {
        ClassScanKind::Run {
            max_classification_overhead,
        } => logical_classifications
            .checked_add(
                simd_run_recoveries
                    .checked_mul(if suffix_inside_class
                        && matches!(operation, Operation::SpanSum | Operation::SpanVisit)
                    {
                        2
                    } else {
                        1
                    })
                    .and_then(|candidates| {
                        candidates.checked_mul(max_classification_overhead)
                    })
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "SIMD class-run recovery classification bound",
                    })?,
            )
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "SIMD class-run physical classification bound",
            })?,
        ClassScanKind::Fixed => logical_classifications
            .checked_div(SIMD_SCALAR_PROOF_BYTES)
            .and_then(|terminating_vectors| terminating_vectors.checked_mul(31))
            .and_then(|overread| logical_classifications.checked_add(overread))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "fixed SIMD class-run physical classification bound",
            })?,
        ClassScanKind::Scalar => logical_classifications,
    };
    let literal_comparisons =
        run_events
            .checked_mul(opposite_literal_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "run events times opposite literal bytes",
            })?;
    let source_reads = finder_scanned_bytes
        .checked_add(classifications)
        .and_then(|value| value.checked_add(literal_comparisons))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "finder, class, and literal source reads",
        })?;
    let minimum_width =
        build
            .literal_bytes
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "minimum match width",
            })?;
    let match_events = input_bytes / minimum_width;
    let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "match event bound as u64",
    })?;
    let span_sum = match operation {
        Operation::Count => 0,
        Operation::SpanSum | Operation::SpanVisit => {
            u64::try_from(input_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "input length as span-sum bound",
            })?
        }
    };
    let work = finder_scanned_bytes
        .checked_mul(FINDER_SCAN_WORK)
        .and_then(|value| {
            finder_calls
                .checked_mul(FINDER_CALL_WORK)
                .and_then(|calls| value.checked_add(calls))
        })
        .and_then(|value| {
            anchor_candidates
                .checked_mul(ANCHOR_CANDIDATE_WORK)
                .and_then(|candidates| value.checked_add(candidates))
        })
        .and_then(|value| {
            classifications
                .checked_mul(CLASSIFICATION_WORK)
                .and_then(|classifications| value.checked_add(classifications))
        })
        .and_then(|value| {
            literal_comparisons
                .checked_mul(LITERAL_COMPARISON_WORK)
                .and_then(|literal| value.checked_add(literal))
        })
        .and_then(|value| {
            run_events
                .checked_mul(RUN_WORK)
                .and_then(|runs| value.checked_add(runs))
        })
        .and_then(|value| {
            match_events
                .checked_mul(MATCH_WORK)
                .and_then(|matches| value.checked_add(matches))
        })
        .and_then(|value| value.checked_add(FIXED_REDUCE_WORK))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "complete reduction work bound",
        })?;
    let scratch_bytes = 0;
    let persistent_bytes = build.persistent_bytes;
    let peak_bytes = persistent_bytes;
    Ok(ReduceUpperBounds {
        input_bytes,
        source_reads,
        finder_scanned_bytes,
        finder_calls,
        anchor_candidates,
        classifications,
        literal_comparisons,
        work,
        run_events,
        candidate_events: run_events,
        match_events,
        count,
        span_sum,
        scratch_bytes,
        persistent_bytes,
        peak_bytes,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the guarded source-free preflight keeps its distinct count and span proof envelopes adjacent"
)]
fn derive_complete_ascii_word_run_upper_bounds(
    build: BuildAccounting,
    class_scan: ClassScanKind,
    input_bytes: usize,
    operation: Operation,
) -> Result<ReduceUpperBounds, ReduceError> {
    let anchor_bytes = build.suffix_bytes;
    let anchor_candidates = input_bytes
        .checked_sub(anchor_bytes)
        .and_then(|remaining| remaining.checked_add(1))
        .unwrap_or(0);
    let finder_calls = anchor_candidates;
    let repeated_anchor_bytes = anchor_candidates
        .checked_mul(
            anchor_bytes
                .checked_sub(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "nonempty guarded suffix overlap width",
                })?,
        )
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "overlapping guarded suffix finder service",
        })?;
    let finder_scanned_bytes =
        input_bytes
            .checked_add(repeated_anchor_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "complete guarded suffix finder service",
            })?;
    let logical_classifications =
        match operation {
            Operation::Count => {
                anchor_candidates
                    .checked_mul(2)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "guarded count boundary classifications",
                    })?
            }
            Operation::SpanSum | Operation::SpanVisit => input_bytes
                .checked_add(anchor_candidates)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "guarded span right probes and backward recovery",
                })?,
        };
    let classifications = match operation {
        Operation::Count => logical_classifications,
        Operation::SpanSum | Operation::SpanVisit => {
            let overhead_per_recovery = match class_scan {
                ClassScanKind::Run {
                    max_classification_overhead,
                } => max_classification_overhead,
                // A terminating fixed-width block can physically classify at
                // most 31 lanes outside its logical backward run.
                ClassScanKind::Fixed => ASCII_WIDE_BYTES - 1,
                ClassScanKind::Scalar => 0,
            };
            logical_classifications
                .checked_add(anchor_candidates.checked_mul(overhead_per_recovery).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "guarded backward scanner physical overhead",
                    },
                )?)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "guarded span physical classifications",
                })?
        }
    };
    let source_reads = finder_scanned_bytes.checked_add(classifications).ok_or(
        ReduceError::ArithmeticOverflow {
            computation: "guarded finder and class source reads",
        },
    )?;
    let minimum_width = anchor_bytes
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "guarded minimum match width",
        })?;
    let match_events = input_bytes / minimum_width;
    let run_events = match operation {
        Operation::Count => 0,
        Operation::SpanSum | Operation::SpanVisit => match_events,
    };
    let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "guarded match event bound as u64",
    })?;
    let span_sum = match operation {
        Operation::Count => 0,
        Operation::SpanSum | Operation::SpanVisit => {
            u64::try_from(input_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "guarded input length as span-sum bound",
            })?
        }
    };
    let work = finder_scanned_bytes
        .checked_mul(FINDER_SCAN_WORK)
        .and_then(|value| {
            finder_calls
                .checked_mul(FINDER_CALL_WORK)
                .and_then(|calls| value.checked_add(calls))
        })
        .and_then(|value| {
            anchor_candidates
                .checked_mul(ANCHOR_CANDIDATE_WORK)
                .and_then(|candidates| value.checked_add(candidates))
        })
        .and_then(|value| {
            classifications
                .checked_mul(CLASSIFICATION_WORK)
                .and_then(|classifications| value.checked_add(classifications))
        })
        .and_then(|value| {
            run_events
                .checked_mul(RUN_WORK)
                .and_then(|runs| value.checked_add(runs))
        })
        .and_then(|value| {
            match_events
                .checked_mul(MATCH_WORK)
                .and_then(|matches| value.checked_add(matches))
        })
        .and_then(|value| value.checked_add(FIXED_REDUCE_WORK))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "complete guarded reduction work bound",
        })?;
    let scratch_bytes = 0;
    let persistent_bytes = build.persistent_bytes;
    let peak_bytes = persistent_bytes;
    Ok(ReduceUpperBounds {
        input_bytes,
        source_reads,
        finder_scanned_bytes,
        finder_calls,
        anchor_candidates,
        classifications,
        literal_comparisons: 0,
        work,
        run_events,
        candidate_events: anchor_candidates,
        match_events,
        count,
        span_sum,
        scratch_bytes,
        persistent_bytes,
        peak_bytes,
    })
}

fn build_ascii_scanner(
    dispatch: Option<(SimdDispatchContext, DispatchPolicy)>,
    class: ByteClass,
    prefer_small_ascii_complement: bool,
    work: &mut BuildWork<'_>,
) -> Result<Option<AsciiClassScanner>, BuildError> {
    let Some((dispatch, policy)) = dispatch else {
        return Ok(None);
    };
    if dispatch.capabilities().usable().contains(Feature::ArmSve) {
        work.charge(SIMD_RUN_SCANNER_BUILD_WORK)?;
        let scanner = if prefer_small_ascii_complement {
            dispatch.ascii_byte_set_run_scanner_prefer_small_complement(class.ascii_set(), policy)
        } else {
            dispatch.ascii_byte_set_run_scanner(class.ascii_set(), policy)
        }
        .expect("the caller supplied an authentic compatible dispatch policy");
        return Ok(Some(AsciiClassScanner::Run(scanner)));
    }
    work.charge(SIMD_FIXED_CLASSIFIER_BUILD_WORK)?;
    Ok(Some(AsciiClassScanner::Fixed(
        dispatch
            .ascii_byte_set_classifier(class.ascii_set(), policy)
            .expect("the caller supplied an authentic compatible dispatch policy"),
    )))
}

/// Admit all literal, storage, and fixed-work resources before consuming the
/// Unicode range iterator. The returned fixed-work offset makes every later
/// proof failure report its exact global work position; boundary and scanner
/// charges remain prospective in `build_inner`.
fn preflight_unicode_class_proof(
    prefix: &[u8],
    suffix: &[u8],
    limits: BuildLimits,
) -> Result<usize, BuildError> {
    if prefix.is_empty() {
        return Err(BuildError::EmptyPrefix);
    }
    if suffix.is_empty() {
        return Err(BuildError::EmptySuffix);
    }
    let literal_bytes =
        prefix
            .len()
            .checked_add(suffix.len())
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "Unicode generalized search literal byte total",
            })?;
    enforce_build(
        literal_bytes,
        limits.max_literal_bytes,
        BuildResource::LiteralBytes,
    )?;
    let persistent_bytes = size_of::<LiteralClassRunSearchPlan>()
        .checked_add(literal_bytes)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "Unicode generalized search persistent bytes",
        })?;
    enforce_build(0, limits.max_scratch_bytes, BuildResource::Scratch)?;
    enforce_build(
        persistent_bytes,
        limits.max_persistent_bytes,
        BuildResource::Persistent,
    )?;
    enforce_build(persistent_bytes, limits.max_peak_bytes, BuildResource::Peak)?;
    let fixed_work = literal_bytes
        .checked_mul(LITERAL_BUILD_WORK_PER_BYTE)
        .and_then(|value| {
            prefix
                .len()
                .checked_mul(FINDER_BUILD_WORK_PER_BYTE)
                .and_then(|finder| value.checked_add(finder))
        })
        .and_then(|value| value.checked_add(FIXED_BUILD_WORK))
        .and_then(|value| value.checked_add(ANCHOR_SELECTION_WORK))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "Unicode generalized search fixed build work",
        })?;
    if fixed_work > limits.max_build_work {
        return Err(BuildError::WorkLimit {
            needed: fixed_work,
            limit: limits.max_build_work,
        });
    }
    // The fixed per-byte charge above admits this single validation pass.
    if !prefix.iter().all(u8::is_ascii) || !suffix.iter().all(u8::is_ascii) {
        return Err(BuildError::NonAsciiUnicodeLiteral);
    }
    Ok(fixed_work)
}

fn prove_unicode_all_non_ascii_class<I>(
    mut ranges: I,
    limits: BuildLimits,
    initial_work: usize,
) -> Result<PreparedClass, BuildError>
where
    I: Iterator<Item = (char, char)>,
{
    let mut class = ByteClass::empty();
    let mut range_count = 0_usize;
    let mut class_members = 0_usize;
    let mut total_work = initial_work;
    let mut previous_end = None;
    let mut next_required = u32::from('\u{80}');
    let maximum = u32::from(char::MAX);
    let mut complete = false;
    loop {
        charge_detached_build_work(&mut total_work, 1, limits.max_build_work)?;
        let Some((start, end)) = ranges.next() else {
            break;
        };
        charge_detached_build_work(
            &mut total_work,
            UNICODE_RANGE_PROOF_WORK,
            limits.max_build_work,
        )?;
        let start = u32::from(start);
        let end = u32::from(end);
        if start > end || previous_end.is_some_and(|previous| previous >= start) {
            return Err(BuildError::NonCanonicalClass);
        }
        previous_end = Some(end);
        range_count = range_count
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "Unicode class range count",
            })?;
        enforce_build(
            range_count,
            limits.max_class_ranges,
            BuildResource::ClassRanges,
        )?;

        if start <= 0x7F {
            let ascii_end = end.min(0x7F);
            let members = usize::try_from(ascii_end - start + 1).map_err(|_| {
                BuildError::ArithmeticOverflow {
                    computation: "Unicode class ASCII range members",
                }
            })?;
            class_members =
                class_members
                    .checked_add(members)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "Unicode class materialized member total",
                    })?;
            enforce_build(
                class_members,
                limits.max_class_members,
                BuildResource::ClassMembers,
            )?;
            charge_detached_build_work(&mut total_work, RANGE_BUILD_WORK, limits.max_build_work)?;
            class.insert_range_with(
                u8::try_from(start).expect("proved ASCII range start"),
                u8::try_from(ascii_end).expect("clamped ASCII range end"),
                |units| charge_detached_build_work(&mut total_work, units, limits.max_build_work),
            )?;
        }

        if complete || end < next_required {
            continue;
        }
        let non_ascii_start = start.max(u32::from('\u{80}'));
        if non_ascii_start > next_required {
            return Err(BuildError::UnsupportedUnicodeClass);
        }
        if end == maximum {
            complete = true;
            continue;
        }
        next_required = end.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
            computation: "next required Unicode scalar",
        })?;
        if (0xD800..=0xDFFF).contains(&next_required) {
            next_required = 0xE000;
        }
    }
    if !complete {
        return Err(BuildError::UnsupportedUnicodeClass);
    }
    let proof_work =
        total_work
            .checked_sub(initial_work)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "Unicode class proof work delta",
            })?;
    Ok(PreparedClass {
        class,
        input_ranges: range_count,
        materialized_members: class_members,
        work: proof_work,
    })
}

fn charge_detached_build_work(
    used: &mut usize,
    units: usize,
    limit: usize,
) -> Result<(), BuildError> {
    let needed = used
        .checked_add(units)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "Unicode class proof work",
        })?;
    if needed > limit {
        return Err(BuildError::WorkLimit { needed, limit });
    }
    *used = needed;
    Ok(())
}

fn build_class<I>(
    ranges: &mut I,
    limits: BuildLimits,
    work: &mut BuildWork<'_>,
) -> Result<(ByteClass, usize, usize), BuildError>
where
    I: Iterator<Item = (u8, u8)>,
{
    let mut class = ByteClass::empty();
    let mut class_ranges = 0_usize;
    let mut class_members = 0_usize;
    let mut previous_end = None;
    loop {
        work.charge(1)?;
        let Some((start, end)) = ranges.next() else {
            break;
        };
        work.charge(RANGE_BUILD_WORK)?;
        if start > end || previous_end.is_some_and(|previous| previous >= start) {
            return Err(BuildError::NonCanonicalClass);
        }
        class_ranges = class_ranges
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "class range count",
            })?;
        enforce_build(
            class_ranges,
            limits.max_class_ranges,
            BuildResource::ClassRanges,
        )?;
        let members = usize::from(end)
            .checked_sub(usize::from(start))
            .and_then(|value| value.checked_add(1))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "class range members",
            })?;
        class_members =
            class_members
                .checked_add(members)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "class member total",
                })?;
        enforce_build(
            class_members,
            limits.max_class_members,
            BuildResource::ClassMembers,
        )?;
        class.insert_range(start, end, work)?;
        previous_end = Some(end);
    }
    if class_ranges == 0 {
        return Err(BuildError::EmptyClass);
    }
    Ok((class, class_ranges, class_members))
}

fn scan_class_run_forward(
    haystack: &[u8],
    class: ByteClass,
    scanner: Option<&AsciiClassScanner>,
    start: usize,
    actual: &mut ReduceActualCounters,
) -> Result<Option<usize>, ReduceError> {
    match scanner {
        Some(AsciiClassScanner::Run(scanner)) => {
            scan_class_run_forward_direct(haystack, scanner, start, actual)
        }
        Some(AsciiClassScanner::Fixed(classifier)) => {
            scan_class_run_forward_fixed(haystack, class, classifier, start, actual)
        }
        None => scan_class_run_forward_scalar(haystack, class, start, actual),
    }
}

fn scan_class_run_forward_value(
    haystack: &[u8],
    class: ByteClass,
    scanner: Option<&AsciiClassScanner>,
    start: usize,
) -> Option<usize> {
    match scanner {
        Some(AsciiClassScanner::Run(scanner)) => {
            scan_class_run_forward_direct_value(haystack, scanner, start)
        }
        Some(AsciiClassScanner::Fixed(classifier)) => {
            scan_class_run_forward_fixed_value(haystack, class, classifier, start)
        }
        None => scan_class_run_forward_scalar_value(haystack, class, start),
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the scanner-reported run is bounded by the suffix passed to the scanner"
)]
fn scan_class_run_forward_direct_value(
    haystack: &[u8],
    scanner: &AsciiByteSetRunScanner,
    start: usize,
) -> Option<usize> {
    let result = scanner.scan_forward(&haystack[start..]);
    let run = result.member_run_len();
    (run != 0).then_some(start + run)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "loop guards prove every fixed-width block and cursor increment remains in the slice"
)]
fn scan_class_run_forward_fixed_value(
    haystack: &[u8],
    class: ByteClass,
    classifier: &AsciiByteSetClassifier,
    start: usize,
) -> Option<usize> {
    let mut end = start;
    for _ in 0..SIMD_SCALAR_PROOF_BYTES {
        if end == haystack.len() {
            return (end != start).then_some(end);
        }
        if !class.contains(haystack[end]) {
            return (end != start).then_some(end);
        }
        end += 1;
    }
    while haystack.len() - end >= ASCII_WIDE_BYTES {
        let block: &[u8; ASCII_WIDE_BYTES] = haystack[end..end + ASCII_WIDE_BYTES]
            .try_into()
            .expect("the fixed-width loop proves a complete block");
        let members = classifier.classify_32(block).member_mask();
        if members == u32::MAX {
            end += ASCII_WIDE_BYTES;
            continue;
        }
        end += usize::try_from(members.trailing_ones()).expect("a 32-bit member prefix fits usize");
        return Some(end);
    }
    while end < haystack.len() && class.contains(haystack[end]) {
        end += 1;
    }
    (end != start).then_some(end)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the loop guard proves each unit cursor increment remains in the slice"
)]
fn scan_class_run_forward_scalar_value(
    haystack: &[u8],
    class: ByteClass,
    start: usize,
) -> Option<usize> {
    let mut end = start;
    while end < haystack.len() && class.contains(haystack[end]) {
        end += 1;
    }
    (end != start).then_some(end)
}

fn scan_class_run_forward_direct(
    haystack: &[u8],
    scanner: &AsciiByteSetRunScanner,
    start: usize,
    actual: &mut ReduceActualCounters,
) -> Result<Option<usize>, ReduceError> {
    let remaining = haystack
        .get(start..)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "forward class run source window",
        })?;
    let result = scanner.scan_forward(remaining);
    charge_classifications(actual, result.examined_bytes())?;
    let run = result.member_run_len();
    if run == 0 {
        return Ok(None);
    }
    start
        .checked_add(run)
        .map(Some)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "forward class run boundary",
        })
}

fn scan_class_run_forward_fixed(
    haystack: &[u8],
    class: ByteClass,
    classifier: &AsciiByteSetClassifier,
    start: usize,
    actual: &mut ReduceActualCounters,
) -> Result<Option<usize>, ReduceError> {
    let mut end = start;
    for _ in 0..SIMD_SCALAR_PROOF_BYTES {
        if end == haystack.len() {
            return Ok((end != start).then_some(end));
        }
        let byte = read_classified(haystack, end, actual)?;
        if !class.contains(byte) {
            return Ok((end != start).then_some(end));
        }
        end = end.checked_add(1).ok_or(ReduceError::ArithmeticOverflow {
            computation: "forward class run scalar proof advance",
        })?;
    }
    while haystack.len().saturating_sub(end) >= ASCII_WIDE_BYTES {
        let members = read_classified_block(haystack, end, classifier, actual)?;
        if members == u32::MAX {
            end = end
                .checked_add(ASCII_WIDE_BYTES)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "forward class run SIMD advance",
                })?;
            continue;
        }
        let prefix = usize::try_from(members.trailing_ones()).map_err(|_| {
            ReduceError::ArithmeticOverflow {
                computation: "forward SIMD member prefix",
            }
        })?;
        end = end
            .checked_add(prefix)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "forward class run terminating SIMD prefix",
            })?;
        return Ok(Some(end));
    }
    while end < haystack.len() {
        let byte = read_classified(haystack, end, actual)?;
        if !class.contains(byte) {
            break;
        }
        end = end.checked_add(1).ok_or(ReduceError::ArithmeticOverflow {
            computation: "forward class run cursor advance",
        })?;
    }
    if end == start {
        return Ok(None);
    }
    Ok(Some(end))
}

fn scan_class_run_forward_scalar(
    haystack: &[u8],
    class: ByteClass,
    start: usize,
    actual: &mut ReduceActualCounters,
) -> Result<Option<usize>, ReduceError> {
    let mut end = start;
    while end < haystack.len() {
        let byte = read_classified(haystack, end, actual)?;
        if !class.contains(byte) {
            break;
        }
        end = end.checked_add(1).ok_or(ReduceError::ArithmeticOverflow {
            computation: "forward scalar class run cursor advance",
        })?;
    }
    Ok((end != start).then_some(end))
}

fn scan_class_run_backward(
    haystack: &[u8],
    class: ByteClass,
    scanner: Option<&AsciiClassScanner>,
    end: usize,
    actual: &mut ReduceActualCounters,
) -> Result<Option<usize>, ReduceError> {
    match scanner {
        Some(AsciiClassScanner::Run(scanner)) => {
            scan_class_run_backward_direct(haystack, scanner, end, actual)
        }
        Some(AsciiClassScanner::Fixed(classifier)) => {
            scan_class_run_backward_fixed(haystack, class, classifier, end, actual)
        }
        None => scan_class_run_backward_scalar(haystack, class, end, actual),
    }
}

fn scan_class_run_backward_value(
    haystack: &[u8],
    class: ByteClass,
    scanner: Option<&AsciiClassScanner>,
    end: usize,
) -> Option<usize> {
    match scanner {
        Some(AsciiClassScanner::Run(scanner)) => {
            let result = scanner.scan_backward(haystack.get(..end)?);
            let run = result.member_run_len();
            (run != 0).then(|| end - run)
        }
        Some(AsciiClassScanner::Fixed(classifier)) => {
            scan_class_run_backward_fixed_value(haystack, class, classifier, end)
        }
        None => scan_class_run_backward_scalar_value(haystack, class, end),
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "loop guards prove each reverse block and cursor decrement remains in the slice"
)]
fn scan_class_run_backward_fixed_value(
    haystack: &[u8],
    class: ByteClass,
    classifier: &AsciiByteSetClassifier,
    end: usize,
) -> Option<usize> {
    let mut start = end;
    for _ in 0..SIMD_SCALAR_PROOF_BYTES {
        if start == 0 {
            return (start != end).then_some(start);
        }
        let previous = start - 1;
        if !class.contains(haystack[previous]) {
            return (start != end).then_some(start);
        }
        start = previous;
    }
    while start >= ASCII_WIDE_BYTES {
        let block_start = start - ASCII_WIDE_BYTES;
        let block: &[u8; ASCII_WIDE_BYTES] = haystack[block_start..start]
            .try_into()
            .expect("the reverse fixed-width loop proves one complete block");
        let members = classifier.classify_32(block).member_mask();
        if members == u32::MAX {
            start = block_start;
            continue;
        }
        start -= usize::try_from(members.leading_ones())
            .expect("a 32-bit member suffix fits usize");
        return Some(start);
    }
    while start > 0 && class.contains(haystack[start - 1]) {
        start -= 1;
    }
    (start != end).then_some(start)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the loop guard proves each reverse cursor decrement remains in the slice"
)]
fn scan_class_run_backward_scalar_value(
    haystack: &[u8],
    class: ByteClass,
    end: usize,
) -> Option<usize> {
    let mut start = end;
    while start > 0 && class.contains(haystack[start - 1]) {
        start -= 1;
    }
    (start != end).then_some(start)
}

fn scan_class_run_backward_direct(
    haystack: &[u8],
    scanner: &AsciiByteSetRunScanner,
    end: usize,
    actual: &mut ReduceActualCounters,
) -> Result<Option<usize>, ReduceError> {
    let preceding = haystack.get(..end).ok_or(ReduceError::ArithmeticOverflow {
        computation: "backward class run source window",
    })?;
    let result = scanner.scan_backward(preceding);
    charge_classifications(actual, result.examined_bytes())?;
    let run = result.member_run_len();
    if run == 0 {
        return Ok(None);
    }
    end.checked_sub(run)
        .map(Some)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "backward class run boundary",
        })
}

fn scan_class_run_backward_fixed(
    haystack: &[u8],
    class: ByteClass,
    classifier: &AsciiByteSetClassifier,
    end: usize,
    actual: &mut ReduceActualCounters,
) -> Result<Option<usize>, ReduceError> {
    let mut start = end;
    for _ in 0..SIMD_SCALAR_PROOF_BYTES {
        if start == 0 {
            return Ok((start != end).then_some(start));
        }
        let previous = start
            .checked_sub(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "backward class run scalar proof position",
            })?;
        let byte = read_classified(haystack, previous, actual)?;
        if !class.contains(byte) {
            return Ok((start != end).then_some(start));
        }
        start = previous;
    }
    while start >= ASCII_WIDE_BYTES {
        let block_start =
            start
                .checked_sub(ASCII_WIDE_BYTES)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "backward class run SIMD block start",
                })?;
        let members = read_classified_block(haystack, block_start, classifier, actual)?;
        if members == u32::MAX {
            start = block_start;
            continue;
        }
        let suffix = usize::try_from(members.leading_ones()).map_err(|_| {
            ReduceError::ArithmeticOverflow {
                computation: "backward SIMD member suffix",
            }
        })?;
        start = start
            .checked_sub(suffix)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "backward class run terminating SIMD suffix",
            })?;
        return Ok(Some(start));
    }
    while start > 0 {
        let previous = start
            .checked_sub(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "backward class run scalar tail position",
            })?;
        let byte = read_classified(haystack, previous, actual)?;
        if !class.contains(byte) {
            break;
        }
        start = previous;
    }
    Ok(Some(start))
}

fn scan_class_run_backward_scalar(
    haystack: &[u8],
    class: ByteClass,
    end: usize,
    actual: &mut ReduceActualCounters,
) -> Result<Option<usize>, ReduceError> {
    let mut start = end;
    while start > 0 {
        let previous = start
            .checked_sub(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "backward scalar class run previous position",
            })?;
        let byte = read_classified(haystack, previous, actual)?;
        if !class.contains(byte) {
            break;
        }
        start = previous;
    }
    Ok((start != end).then_some(start))
}

fn read_classified_block(
    haystack: &[u8],
    start: usize,
    classifier: &AsciiByteSetClassifier,
    actual: &mut ReduceActualCounters,
) -> Result<u32, ReduceError> {
    let end = start
        .checked_add(ASCII_WIDE_BYTES)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "classified SIMD block end",
        })?;
    let block: &[u8; ASCII_WIDE_BYTES] = haystack
        .get(start..end)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "classified SIMD block source",
        })?
        .try_into()
        .map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "classified SIMD block width",
        })?;
    charge_classifications(actual, ASCII_WIDE_BYTES)?;
    Ok(classifier.classify_32(block).member_mask())
}

fn charge_finder_scan(actual: &mut ReduceActualCounters, bytes: usize) -> Result<(), ReduceError> {
    actual.finder_scanned_bytes = checked_add(
        actual.finder_scanned_bytes,
        bytes,
        "actual finder scanned bytes",
    )?;
    let work = bytes
        .checked_mul(FINDER_SCAN_WORK)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "finder scan work",
        })?;
    actual.work = checked_add(actual.work, work, "actual finder scan work")?;
    Ok(())
}

fn read_classified(
    haystack: &[u8],
    position: usize,
    actual: &mut ReduceActualCounters,
) -> Result<u8, ReduceError> {
    let byte = *haystack
        .get(position)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "classified source position",
        })?;
    charge_classifications(actual, 1)?;
    Ok(byte)
}

fn charge_classifications(
    actual: &mut ReduceActualCounters,
    amount: usize,
) -> Result<(), ReduceError> {
    actual.classifications = checked_add(actual.classifications, amount, "actual classifications")?;
    let work = amount
        .checked_mul(CLASSIFICATION_WORK)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "classification work",
        })?;
    actual.work = checked_add(actual.work, work, "classification work")?;
    Ok(())
}

fn literal_equals(
    haystack: &[u8],
    start: usize,
    literal: &[u8],
    actual: &mut ReduceActualCounters,
) -> Result<bool, ReduceError> {
    for (offset, &expected) in literal.iter().enumerate() {
        let position = start
            .checked_add(offset)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "literal comparison position",
            })?;
        let actual_byte = *haystack
            .get(position)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "literal comparison source position",
            })?;
        actual.literal_comparisons =
            checked_add(actual.literal_comparisons, 1, "actual literal comparisons")?;
        actual.work = checked_add(
            actual.work,
            LITERAL_COMPARISON_WORK,
            "literal comparison work",
        )?;
        if actual_byte != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

fn search_scan_class_run_forward(
    haystack: &[u8],
    class: ByteClass,
    scanner: Option<&AsciiClassScanner>,
    start: usize,
    actual: &mut ReduceActualCounters,
    meter: SearchMeter,
) -> Result<Option<usize>, SearchError> {
    if meter.work_envelope_admitted {
        return scan_class_run_forward(haystack, class, scanner, start, actual)
            .map_err(SearchError::from);
    }
    if start == haystack.len() {
        return Ok(None);
    }
    let capacity = meter.service_capacity(actual, CLASSIFICATION_WORK)?;
    if capacity == 0 {
        meter.ensure_work(actual, CLASSIFICATION_WORK)?;
        return Err(SearchError::Kernel(ReduceError::AccountingInvariant {
            resource: "metered forward classification capacity",
            actual: 1,
            upper: 0,
        }));
    }
    let bounded_end = start.saturating_add(capacity).min(haystack.len());
    let bounded = haystack
        .get(..bounded_end)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "metered forward class window",
        })?;
    let recovered = scan_class_run_forward_scalar(bounded, class, start, actual)?;
    if bounded_end < haystack.len() && recovered == Some(bounded_end) {
        meter.ensure_work(actual, CLASSIFICATION_WORK)?;
        return Err(SearchError::Kernel(ReduceError::AccountingInvariant {
            resource: "metered forward class continuation",
            actual: 1,
            upper: 0,
        }));
    }
    Ok(recovered)
}

fn scan_unicode_all_non_ascii_run_forward(
    haystack: &[u8],
    class: ByteClass,
    scanner: Option<&AsciiClassScanner>,
    start: usize,
    actual: &mut ReduceActualCounters,
) -> Result<Option<usize>, ReduceError> {
    let mut end = scan_class_run_forward(haystack, class, scanner, start, actual)?.unwrap_or(start);
    if end == haystack.len() {
        return Ok((end != start).then_some(end));
    }

    // Consecutive non-ASCII scalars stay on the decoder. When an ASCII member
    // reappears, consume it and resume the retained ASCII scanner only after
    // its leaf-specific scalar proof. That recovers long ASCII tails without
    // issuing a wide scan for every short Unicode/ASCII alternation.
    loop {
        let remaining = haystack.get(end..).ok_or(ReduceError::ArithmeticOverflow {
            computation: "Unicode class-run decode window",
        })?;
        let decoded = decode_scalar(remaining);
        charge_classifications(actual, decoded.byte_checks)?;
        let Some(scalar) = decoded.scalar else {
            return Ok((end != start).then_some(end));
        };
        let ascii_member = if scalar <= 0x7F {
            let byte = u8::try_from(scalar).expect("ASCII scalar fits u8");
            if !class.contains(byte) {
                return Ok((end != start).then_some(end));
            }
            true
        } else {
            false
        };
        end = end
            .checked_add(decoded.width)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "Unicode class-run scalar advance",
            })?;
        if end == haystack.len() {
            return Ok(Some(end));
        }
        if ascii_member {
            end = resume_unicode_ascii_corridor(haystack, class, scanner, end, actual)?;
            if end == haystack.len() {
                return Ok(Some(end));
            }
        }
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the decoder width and resumed corridor are each bounded by the remaining slice"
)]
fn scan_unicode_all_non_ascii_run_forward_value(
    haystack: &[u8],
    class: ByteClass,
    scanner: Option<&AsciiClassScanner>,
    start: usize,
) -> Option<usize> {
    // Run scanners may spend a fixed-width setup cost only to recover a
    // boundary in their first block. The accounting-free projection can
    // instead use the same bounded scalar proof already used when an ASCII
    // corridor resumes after Unicode decoding, then hand only a sustained
    // corridor to the retained scanner. Fixed classifiers and scalar plans
    // keep their ordinary initial scan.
    let mut end = match scanner {
        Some(AsciiClassScanner::Run(scanner)) => {
            scan_unicode_ascii_corridor_after_scalar_proof_value(
                haystack, class, scanner, start,
            )
        }
        Some(AsciiClassScanner::Fixed(_)) | None => {
            scan_class_run_forward_value(haystack, class, scanner, start).unwrap_or(start)
        }
    };
    if end == haystack.len() {
        return (end != start).then_some(end);
    }

    loop {
        let decoded = decode_scalar(&haystack[end..]);
        let Some(scalar) = decoded.scalar else {
            return (end != start).then_some(end);
        };
        let ascii_member = if scalar <= 0x7F {
            let byte = u8::try_from(scalar).expect("ASCII scalar fits u8");
            if !class.contains(byte) {
                return (end != start).then_some(end);
            }
            true
        } else {
            false
        };
        end += decoded.width;
        if end == haystack.len() {
            return Some(end);
        }
        if ascii_member {
            end = resume_unicode_ascii_corridor_value(haystack, class, scanner, end);
            if end == haystack.len() {
                return Some(end);
            }
        }
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the loop guard proves each unit cursor increment remains in the slice"
)]
fn resume_unicode_ascii_corridor_value(
    haystack: &[u8],
    class: ByteClass,
    scanner: Option<&AsciiClassScanner>,
    start: usize,
) -> usize {
    match scanner {
        None => start,
        Some(AsciiClassScanner::Fixed(classifier)) => {
            scan_class_run_forward_fixed_value(haystack, class, classifier, start).unwrap_or(start)
        }
        Some(AsciiClassScanner::Run(scanner)) => {
            scan_unicode_ascii_corridor_after_scalar_proof_value(
                haystack, class, scanner, start,
            )
        }
    }
}

#[inline(never)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the scalar proof and scanner-reported continuation are disjoint ranges bounded by the source slice"
)]
fn scan_unicode_ascii_corridor_after_scalar_proof_value(
    haystack: &[u8],
    class: ByteClass,
    scanner: &AsciiByteSetRunScanner,
    start: usize,
) -> usize {
    let mut end = start;
    for _ in 0..scanner.max_classification_overhead() {
        if end == haystack.len() || !class.contains(haystack[end]) {
            return end;
        }
        end += 1;
    }
    scan_class_run_forward_direct_value(haystack, scanner, end).unwrap_or(end)
}

fn resume_unicode_ascii_corridor(
    haystack: &[u8],
    class: ByteClass,
    scanner: Option<&AsciiClassScanner>,
    start: usize,
    actual: &mut ReduceActualCounters,
) -> Result<usize, ReduceError> {
    match scanner {
        None => Ok(start),
        Some(AsciiClassScanner::Fixed(classifier)) => {
            scan_class_run_forward_fixed(haystack, class, classifier, start, actual)
                .map(|end| end.unwrap_or(start))
        }
        Some(AsciiClassScanner::Run(scanner)) => {
            let mut end = start;
            for _ in 0..scanner.max_classification_overhead() {
                if end == haystack.len() {
                    return Ok(end);
                }
                let byte = read_classified(haystack, end, actual)?;
                if !class.contains(byte) {
                    return Ok(end);
                }
                end = end.checked_add(1).ok_or(ReduceError::ArithmeticOverflow {
                    computation: "resumed Unicode ASCII scalar proof advance",
                })?;
            }
            scan_class_run_forward_direct(haystack, scanner, end, actual)
                .map(|recovered| recovered.unwrap_or(end))
        }
    }
}

fn search_scan_unicode_all_non_ascii_run_forward(
    haystack: &[u8],
    class: ByteClass,
    scanner: Option<&AsciiClassScanner>,
    start: usize,
    actual: &mut ReduceActualCounters,
    meter: SearchMeter,
) -> Result<Option<usize>, SearchError> {
    if meter.work_envelope_admitted {
        return scan_unicode_all_non_ascii_run_forward(haystack, class, scanner, start, actual)
            .map_err(SearchError::from);
    }
    // Finite-work execution remains scalar so every source dereference is
    // preceded immediately by its prospective work admission.
    let mut end = start;
    while end < haystack.len() {
        let remaining = haystack.get(end..).ok_or(ReduceError::ArithmeticOverflow {
            computation: "metered Unicode class-run decode window",
        })?;
        let decoded = decode_scalar_with(remaining, || {
            meter.ensure_work(actual, CLASSIFICATION_WORK)?;
            charge_classifications(actual, 1)?;
            Ok::<(), SearchError>(())
        })?;
        let Some(scalar) = decoded.scalar else {
            return Ok((end != start).then_some(end));
        };
        if scalar <= 0x7F && !class.contains(u8::try_from(scalar).expect("ASCII scalar fits u8")) {
            return Ok((end != start).then_some(end));
        }
        end = end
            .checked_add(decoded.width)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "metered Unicode class-run scalar advance",
            })?;
    }
    Ok((end != start).then_some(end))
}

fn search_scan_class_run_backward(
    haystack: &[u8],
    class: ByteClass,
    scanner: Option<&AsciiClassScanner>,
    end: usize,
    actual: &mut ReduceActualCounters,
    meter: SearchMeter,
) -> Result<Option<usize>, SearchError> {
    if meter.work_envelope_admitted {
        return scan_class_run_backward(haystack, class, scanner, end, actual)
            .map_err(SearchError::from);
    }
    if end == 0 {
        return Ok(None);
    }
    let capacity = meter.service_capacity(actual, CLASSIFICATION_WORK)?;
    if capacity == 0 {
        meter.ensure_work(actual, CLASSIFICATION_WORK)?;
        return Err(SearchError::Kernel(ReduceError::AccountingInvariant {
            resource: "metered backward classification capacity",
            actual: 1,
            upper: 0,
        }));
    }
    let bounded_start = end.saturating_sub(capacity);
    let bounded = haystack
        .get(bounded_start..end)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "metered backward class window",
        })?;
    let recovered = scan_class_run_backward_scalar(bounded, class, bounded.len(), actual)?;
    if bounded_start != 0 && recovered == Some(0) {
        meter.ensure_work(actual, CLASSIFICATION_WORK)?;
        return Err(SearchError::Kernel(ReduceError::AccountingInvariant {
            resource: "metered backward class continuation",
            actual: 1,
            upper: 0,
        }));
    }
    recovered
        .map(|relative| {
            bounded_start
                .checked_add(relative)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "absolute metered backward class boundary",
                })
        })
        .transpose()
        .map_err(SearchError::from)
}

fn search_read_classified(
    haystack: &[u8],
    position: usize,
    actual: &mut ReduceActualCounters,
    meter: SearchMeter,
) -> Result<u8, SearchError> {
    meter.ensure_work(actual, CLASSIFICATION_WORK)?;
    read_classified(haystack, position, actual).map_err(SearchError::from)
}

fn search_literal_equals(
    haystack: &[u8],
    start: usize,
    literal: &[u8],
    actual: &mut ReduceActualCounters,
    meter: SearchMeter,
) -> Result<bool, SearchError> {
    for (offset, &expected) in literal.iter().enumerate() {
        meter.ensure_work(actual, LITERAL_COMPARISON_WORK)?;
        let position = start
            .checked_add(offset)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "metered literal comparison position",
            })?;
        let actual_byte = *haystack
            .get(position)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "metered literal comparison source position",
            })?;
        actual.literal_comparisons =
            checked_add(actual.literal_comparisons, 1, "metered literal comparisons")?;
        actual.work = checked_add(
            actual.work,
            LITERAL_COMPARISON_WORK,
            "metered literal comparison work",
        )?;
        if actual_byte != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

fn verify_actual(
    actual: ReduceActualCounters,
    upper: ReduceUpperBounds,
) -> Result<(), ReduceError> {
    verify("source reads", actual.source_reads, upper.source_reads)?;
    verify(
        "finder scanned bytes",
        actual.finder_scanned_bytes,
        upper.finder_scanned_bytes,
    )?;
    verify("finder calls", actual.finder_calls, upper.finder_calls)?;
    verify(
        "anchor candidates",
        actual.anchor_candidates,
        upper.anchor_candidates,
    )?;
    verify(
        "classifications",
        actual.classifications,
        upper.classifications,
    )?;
    verify(
        "literal comparisons",
        actual.literal_comparisons,
        upper.literal_comparisons,
    )?;
    verify("runs", actual.runs, upper.run_events)?;
    verify("candidates", actual.candidates, upper.candidate_events)?;
    verify("matches", actual.matches, upper.match_events)?;
    verify("count", actual.count, upper.count)?;
    verify("span sum", actual.span_sum, upper.span_sum)?;
    verify("work", actual.work, upper.work)?;
    verify("scratch bytes", actual.scratch_bytes, upper.scratch_bytes)
}

fn verify(
    resource: &'static str,
    actual: impl TryInto<u64>,
    upper: impl TryInto<u64>,
) -> Result<(), ReduceError> {
    let actual = actual
        .try_into()
        .map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "actual counter as u64",
        })?;
    let upper = upper
        .try_into()
        .map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "upper bound as u64",
        })?;
    if actual > upper {
        return Err(ReduceError::AccountingInvariant {
            resource,
            actual,
            upper,
        });
    }
    Ok(())
}

fn checked_add(left: usize, right: usize, computation: &'static str) -> Result<usize, ReduceError> {
    left.checked_add(right)
        .ok_or(ReduceError::ArithmeticOverflow { computation })
}

fn copy_literal(source: &[u8], structure: &'static str) -> Result<Box<[u8]>, BuildError> {
    fre_exact_alloc::copy_exact(source)
        .map(Vec::into_boxed_slice)
        .map_err(|error| match error {
            CopyError::LayoutOverflow => BuildError::ArithmeticOverflow {
                computation: "exact literal allocation layout",
            },
            CopyError::AllocationFailed => BuildError::AllocationFailed {
                structure,
                bytes: source.len(),
            },
        })
}

struct BuildWork<'a> {
    used: usize,
    limit: usize,
    actual: &'a mut DirectBuildAttemptActual,
}

impl<'a> BuildWork<'a> {
    const fn new(limit: usize, actual: &'a mut DirectBuildAttemptActual) -> Self {
        Self {
            used: 0,
            limit,
            actual,
        }
    }

    fn charge(&mut self, units: usize) -> Result<(), BuildError> {
        let needed = self
            .used
            .checked_add(units)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "charged build work",
            })?;
        if needed > self.limit {
            return Err(BuildError::WorkLimit {
                needed,
                limit: self.limit,
            });
        }
        self.used = needed;
        self.actual.work = self
            .actual
            .work
            .checked_add(
                u64::try_from(units).map_err(|_| BuildError::ArithmeticOverflow {
                    computation: "exact build work conversion",
                })?,
            )
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "exact build work",
            })?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum BuildResource {
    LiteralBytes,
    ClassRanges,
    ClassMembers,
    Scratch,
    Persistent,
    Peak,
}

fn enforce_build(needed: usize, limit: usize, resource: BuildResource) -> Result<(), BuildError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        BuildResource::LiteralBytes => BuildError::LiteralBytesLimit { needed, limit },
        BuildResource::ClassRanges => BuildError::ClassRangesLimit { needed, limit },
        BuildResource::ClassMembers => BuildError::ClassMembersLimit { needed, limit },
        BuildResource::Scratch => BuildError::ScratchLimit { needed, limit },
        BuildResource::Persistent => BuildError::PersistentLimit { needed, limit },
        BuildResource::Peak => BuildError::PeakLimit { needed, limit },
    })
}

fn record_literal_copy(
    actual: &mut DirectBuildAttemptActual,
    bytes: usize,
) -> Result<(), BuildError> {
    actual.allocations =
        actual
            .allocations
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "exact allocation count",
            })?;
    actual.allocated_bytes =
        actual
            .allocated_bytes
            .checked_add(bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "exact allocated bytes",
            })?;
    actual.copied_bytes =
        actual
            .copied_bytes
            .checked_add(bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "exact copied bytes",
            })?;
    actual.initialized_bytes =
        actual
            .initialized_bytes
            .checked_add(bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "exact initialized bytes",
            })?;
    actual.live_persistent_bytes =
        actual
            .live_persistent_bytes
            .checked_add(bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "exact live persistent bytes",
            })?;
    actual.peak_bytes = actual.peak_bytes.max(actual.live_persistent_bytes);
    Ok(())
}

#[derive(Clone, Copy)]
enum ReduceResource {
    InputBytes,
    SourceReads,
    Work,
    RunEvents,
    MatchEvents,
    Scratch,
    Persistent,
    Peak,
}

fn enforce_upper_bounds(upper: ReduceUpperBounds, limits: ReduceLimits) -> Result<(), ReduceError> {
    for (needed, limit, resource) in [
        (
            upper.input_bytes,
            limits.max_input_bytes,
            ReduceResource::InputBytes,
        ),
        (
            upper.source_reads,
            limits.max_source_reads,
            ReduceResource::SourceReads,
        ),
        (upper.work, limits.max_work, ReduceResource::Work),
        (
            upper.run_events,
            limits.max_run_events,
            ReduceResource::RunEvents,
        ),
        (
            upper.match_events,
            limits.max_match_events,
            ReduceResource::MatchEvents,
        ),
        (
            upper.scratch_bytes,
            limits.max_scratch_bytes,
            ReduceResource::Scratch,
        ),
        (
            upper.persistent_bytes,
            limits.max_persistent_bytes,
            ReduceResource::Persistent,
        ),
        (
            upper.peak_bytes,
            limits.max_peak_bytes,
            ReduceResource::Peak,
        ),
    ] {
        enforce_reduce(needed, limit, resource)?;
    }
    if upper.count > limits.max_count {
        return Err(ReduceError::CountLimit {
            needed: upper.count,
            limit: limits.max_count,
        });
    }
    if upper.span_sum > limits.max_span_sum {
        return Err(ReduceError::SpanSumLimit {
            needed: upper.span_sum,
            limit: limits.max_span_sum,
        });
    }
    Ok(())
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
        ReduceResource::SourceReads => ReduceError::SourceReadsLimit { needed, limit },
        ReduceResource::Work => ReduceError::WorkLimit { needed, limit },
        ReduceResource::RunEvents => ReduceError::RunEventsLimit { needed, limit },
        ReduceResource::MatchEvents => ReduceError::MatchEventsLimit { needed, limit },
        ReduceResource::Scratch => ReduceError::ScratchLimit { needed, limit },
        ReduceResource::Persistent => ReduceError::PersistentLimit { needed, limit },
        ReduceResource::Peak => ReduceError::PeakLimit { needed, limit },
    })
}

#[cfg(test)]
mod tests {
    use core::ops::Range;

    use regex::bytes::RegexBuilder;

    use super::*;

    const RANGES: [(u8, u8); 2] = [(b'\t', b'\r'), (b' ', b' ')];
    const ASCII_WORD_RANGES: [(u8, u8); 4] =
        [(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')];

    fn bounded_test_auto_scanner_has_vector() -> bool {
        let dispatch = SimdDispatchContext::capture();
        let set = AsciiByteSet::from_words([1_u64 << u32::from(b'0'), 0]);
        let scanner = if dispatch.capabilities().usable().contains(Feature::ArmSve) {
            AsciiClassScanner::Run(
                dispatch
                    .ascii_byte_set_run_scanner(set, DispatchPolicy::Auto)
                    .unwrap(),
            )
        } else {
            AsciiClassScanner::Fixed(
                dispatch
                    .ascii_byte_set_classifier(set, DispatchPolicy::Auto)
                    .unwrap(),
            )
        };
        bounded_ascii_scanner_has_vector(Some(&scanner))
    }

    fn plan() -> LiteralClassRunLiteralPlan {
        LiteralClassRunLiteralPlan::build(
            b"ab",
            RANGES.into_iter(),
            b"cd",
            BuildLimits::unlimited(),
        )
        .unwrap()
    }

    fn complete_ascii_word_run_plan(suffix: &[u8]) -> LiteralClassRunLiteralPlan {
        LiteralClassRunLiteralPlan::build_complete_ascii_word_run(
            b"",
            ASCII_WORD_RANGES.into_iter(),
            suffix,
            BuildLimits::unlimited(),
        )
        .unwrap()
    }

    fn generalized_plan(
        prefix: &[u8],
        ranges: impl Iterator<Item = (u8, u8)>,
        suffix: &[u8],
        minimum: SearchRunMinimum,
    ) -> LiteralClassRunSearchPlan {
        LiteralClassRunSearchPlan::build(
            prefix,
            ranges,
            suffix,
            minimum,
            BoundarySemantics::Unguarded,
            BuildLimits::unlimited(),
        )
        .unwrap()
    }

    fn bounded_plan() -> BoundedLiteralClassRunPlan {
        BoundedLiteralClassRunPlan::build(
            b"ab",
            [(b'0', b'1')].into_iter(),
            b"xy",
            0,
            2,
            BuildLimits::unlimited(),
        )
        .unwrap()
    }

    fn bounded_prefix_order(
        plan: &BoundedLiteralClassRunPlan,
        haystack: &[u8],
    ) -> Vec<(usize, usize)> {
        let mut spans = Vec::new();
        for start in 0..=haystack.len() {
            let Some(remaining) = haystack.get(start..) else {
                continue;
            };
            if !remaining.starts_with(plan.prefix()) {
                continue;
            }
            let mut run_end = start + plan.prefix().len();
            while run_end < haystack.len() && plan.class.contains(haystack[run_end]) {
                run_end += 1;
            }
            let run_len = run_end - start - plan.prefix().len();
            if run_len >= plan.minimum
                && run_len <= plan.maximum
                && haystack
                    .get(run_end..)
                    .is_some_and(|remaining| remaining.starts_with(plan.suffix()))
            {
                spans.push((start, run_end + plan.suffix().len()));
            }
        }
        spans
    }

    fn bounded_suffix_order(
        plan: &BoundedLiteralClassRunPlan,
        haystack: &[u8],
    ) -> Vec<(usize, usize)> {
        let mut spans = Vec::new();
        for suffix_start in 0..=haystack.len() {
            let Some(remaining) = haystack.get(suffix_start..) else {
                continue;
            };
            if !remaining.starts_with(plan.suffix()) {
                continue;
            }
            let mut run_start = suffix_start;
            while run_start > 0 && plan.class.contains(haystack[run_start - 1]) {
                run_start -= 1;
            }
            let run_len = suffix_start - run_start;
            if run_len < plan.minimum || run_len > plan.maximum {
                continue;
            }
            let Some(start) = run_start.checked_sub(plan.prefix().len()) else {
                continue;
            };
            if haystack.get(start..run_start) == Some(plan.prefix()) {
                spans.push((start, suffix_start + plan.suffix().len()));
            }
        }
        spans
    }

    fn assert_bounded_orders_are_isomorphic(
        plan: &BoundedLiteralClassRunPlan,
        haystack: &[u8],
    ) -> Vec<(usize, usize)> {
        let prefix_order = bounded_prefix_order(plan, haystack);
        let suffix_order = bounded_suffix_order(plan, haystack);
        assert_eq!(prefix_order, suffix_order, "haystack={haystack:?}");
        for pair in prefix_order.windows(2) {
            assert!(pair[0].0 < pair[1].0, "haystack={haystack:?}");
            assert!(pair[0].1 < pair[1].1, "haystack={haystack:?}");
        }
        prefix_order
    }

    fn assert_bounded_projection_limit_parity(
        plan: &BoundedLiteralClassRunPlan,
        haystack: &[u8],
    ) {
        let window = Window::full(haystack);
        let (selected, selected_accounting) = plan
            .find_window(haystack, window, SearchLimits::unlimited())
            .unwrap();
        let (shortest, shortest_accounting) = plan
            .shortest_window(haystack, window, SearchLimits::unlimited())
            .unwrap();
        let (exists, exists_accounting) = plan
            .is_match_window(haystack, window, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(shortest, selected.map(|(_, end)| end));
        assert_eq!(exists, selected.is_some());
        assert_eq!(selected_accounting.operation_id, BOUNDED_SEARCH_OPERATION_ID);
        assert_eq!(
            shortest_accounting.operation_id,
            BOUNDED_SHORTEST_SEARCH_OPERATION_ID
        );
        assert_eq!(
            exists_accounting.operation_id,
            BOUNDED_EXISTS_SEARCH_OPERATION_ID
        );
        assert_eq!(
            selected_accounting.candidate_visits,
            shortest_accounting.candidate_visits
        );
        assert_eq!(
            selected_accounting.candidate_visits,
            exists_accounting.candidate_visits
        );
        assert_eq!(selected_accounting.work, shortest_accounting.work);
        assert_eq!(selected_accounting.work, exists_accounting.work);
        assert!(selected_accounting.candidate_visits >= 2);

        let exact_work = u64::try_from(selected_accounting.work).unwrap();
        let exact = SearchLimits {
            max_work_upper_bound: exact_work,
            max_candidate_visits: selected_accounting.candidate_visits,
            max_scratch_bytes: 0,
        };
        assert_eq!(plan.find_window(haystack, window, exact).unwrap().0, selected);
        assert_eq!(
            plan.find_window_value(haystack, window, exact).unwrap(),
            selected
        );
        assert_eq!(
            plan.shortest_window(haystack, window, exact).unwrap().0,
            shortest
        );
        assert_eq!(
            plan.shortest_window_value(haystack, window, exact).unwrap(),
            shortest
        );
        assert_eq!(
            plan.is_match_window(haystack, window, exact).unwrap().0,
            exists
        );
        assert_eq!(
            plan.is_match_window_value(haystack, window, exact)
                .unwrap(),
            exists
        );

        let work_below = SearchLimits {
            max_work_upper_bound: exact_work - 1,
            max_candidate_visits: usize::MAX,
            max_scratch_bytes: 0,
        };
        assert_eq!(
            plan.find_window(haystack, window, work_below)
                .unwrap_err(),
            plan.find_window_value(haystack, window, work_below)
                .unwrap_err()
        );
        assert_eq!(
            plan.shortest_window(haystack, window, work_below)
                .unwrap_err(),
            plan.shortest_window_value(haystack, window, work_below)
                .unwrap_err()
        );
        assert_eq!(
            plan.is_match_window(haystack, window, work_below)
                .unwrap_err(),
            plan.is_match_window_value(haystack, window, work_below)
                .unwrap_err()
        );
        assert!(matches!(
            plan.find_window(haystack, window, work_below)
                .unwrap_err(),
            SearchError::WorkLimit { .. }
        ));

        let candidates_below = SearchLimits {
            max_work_upper_bound: u64::MAX,
            max_candidate_visits: selected_accounting.candidate_visits - 1,
            max_scratch_bytes: 0,
        };
        assert_eq!(
            plan.find_window(haystack, window, candidates_below)
                .unwrap_err(),
            plan.find_window_value(haystack, window, candidates_below)
                .unwrap_err()
        );
        assert_eq!(
            plan.shortest_window(haystack, window, candidates_below)
                .unwrap_err(),
            plan.shortest_window_value(haystack, window, candidates_below)
                .unwrap_err()
        );
        assert_eq!(
            plan.is_match_window(haystack, window, candidates_below)
                .unwrap_err(),
            plan.is_match_window_value(haystack, window, candidates_below)
                .unwrap_err()
        );
        assert!(matches!(
            plan.find_window(haystack, window, candidates_below)
                .unwrap_err(),
            SearchError::CandidateLimit { .. }
        ));
    }

    fn unicode_generalized_plan() -> LiteralClassRunSearchPlan {
        LiteralClassRunSearchPlan::build_unicode_all_non_ascii(
            b"a",
            [
                ('\0', '\u{9}'),
                ('\u{B}', '\u{C}'),
                ('\u{E}', 'y'),
                ('{', char::MAX),
            ]
            .into_iter(),
            b"z",
            SearchRunMinimum::Zero,
            BuildLimits::unlimited(),
        )
        .unwrap()
    }

    fn reference(pattern: &str, haystack: &[u8]) -> (u64, u64, Vec<Range<usize>>) {
        let spans: Vec<_> = RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .map(|matched| matched.start()..matched.end())
            .collect();
        let count = u64::try_from(spans.len()).unwrap();
        let sum = spans
            .iter()
            .map(|span| u64::try_from(span.end - span.start).unwrap())
            .sum();
        (count, sum, spans)
    }

    fn assert_exhaustive_matches(
        plan: &LiteralClassRunLiteralPlan,
        pattern: &str,
        alphabet: &[u8],
        maximum_length: usize,
    ) {
        let oracle = RegexBuilder::new(pattern).unicode(false).build().unwrap();
        for length in 0_usize..=maximum_length {
            let cases = alphabet.len().pow(u32::try_from(length).unwrap());
            for mut ordinal in 0..cases {
                let mut haystack = vec![0; length];
                for byte in &mut haystack {
                    *byte = alphabet[ordinal % alphabet.len()];
                    ordinal /= alphabet.len();
                }
                let spans: Vec<_> = oracle
                    .find_iter(&haystack)
                    .map(|matched| matched.start()..matched.end())
                    .collect();
                let count = u64::try_from(spans.len()).unwrap();
                let sum = spans
                    .iter()
                    .map(|span| u64::try_from(span.end - span.start).unwrap())
                    .sum();
                assert_eq!(
                    plan.count(&haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .count,
                    count,
                    "pattern={pattern:?} haystack={haystack:?}"
                );
                assert_eq!(
                    plan.span_sum(&haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .span_sum,
                    sum,
                    "pattern={pattern:?} haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    fn matches_greedy_nonoverlap_reference() {
        let plan = plan();
        for haystack in [
            b"".as_slice(),
            b"ab cd",
            b"ab\t\tcd--ab \r\ncd",
            b"zab cdab  cd",
            b"abxcd ab  ce ab   cd",
            b"abab cdcd ab cd",
            b"\xffab \tcd\x80ab\ncd",
        ] {
            let (count, sum, _) = reference(r"ab\s+cd", haystack);
            assert_eq!(
                plan.count(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count,
                count,
                "haystack={haystack:?}"
            );
            assert_eq!(
                plan.span_sum(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .span_sum,
                sum,
                "haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn span_visit_matches_every_reduction_route_and_span_accounting() {
        let suffix_anchored = LiteralClassRunLiteralPlan::build(
            b"a",
            [(b'x', b'x')].into_iter(),
            b"zzzz",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let suffix_inside_class = LiteralClassRunLiteralPlan::build(
            b"",
            [(b'a', b'a')].into_iter(),
            b"aa",
            BuildLimits::unlimited(),
        )
        .unwrap();
        for (plan, pattern, haystack) in [
            (plan(), r"ab\s+cd", b"ab cd--ab \tcd".as_slice()),
            (
                suffix_anchored,
                r"ax+zzzz",
                b"axxxzzzz--axzzzz".as_slice(),
            ),
            (
                suffix_inside_class,
                r"a+aa",
                b"baaaabaaaaa".as_slice(),
            ),
            (
                complete_ascii_word_run_plan(b"nn"),
                r"\b\w+nn\b",
                b"!ann!bnn?nnnn.".as_slice(),
            ),
        ] {
            let (_, expected_sum, expected_ranges) = reference(pattern, haystack);
            let expected: Vec<_> = expected_ranges
                .into_iter()
                .map(|range| CompleteSpan {
                    start: range.start,
                    end: range.end,
                })
                .collect();
            let spanned = plan
                .span_sum(haystack, ReduceLimits::unlimited())
                .unwrap();
            let mut visited = Vec::new();
            let result = plan
                .visit_spans(haystack, ReduceLimits::unlimited(), |span| {
                    visited.push(span);
                })
                .unwrap();
            assert_eq!(visited, expected, "pattern={pattern:?}");
            assert_eq!(result.matches, expected.len(), "pattern={pattern:?}");
            assert_eq!(result.span_sum, expected_sum, "pattern={pattern:?}");
            assert_eq!(result.span_sum, spanned.span_sum, "pattern={pattern:?}");
            assert_eq!(result.accounting.actual, spanned.accounting.actual);
            assert_eq!(
                result.accounting.upper_bounds,
                spanned.accounting.upper_bounds
            );
            assert_eq!(result.accounting.identity, plan.span_visit_identity());
            assert_eq!(
                result.accounting.identity.operation_id,
                SPAN_VISIT_OPERATION_ID
            );
            assert_eq!(result.accounting.actual.scratch_bytes, 0);
        }
    }

    #[test]
    fn span_visit_refuses_before_the_first_callback() {
        let plan = plan();
        let mut callbacks = 0_usize;
        let error = plan
            .visit_spans(
                b"ab cd",
                ReduceLimits {
                    max_span_sum: 4,
                    ..ReduceLimits::unlimited()
                },
                |_| callbacks += 1,
            )
            .unwrap_err();
        assert_eq!(callbacks, 0);
        assert!(matches!(
            error,
            ReduceError::SpanSumLimit {
                needed: 5,
                limit: 4
            }
        ));
    }

    #[test]
    fn generalized_selected_and_earliest_window_keep_distinct_greedy_projections() {
        let plan = generalized_plan(
            b"a",
            [(b'b', b'c')].into_iter(),
            b"",
            SearchRunMinimum::Zero,
        );
        let haystack = b"!abcb!ac!";
        let window = Window::new(1, 5);
        let (selected, selected_accounting) = plan
            .find_window(haystack, window, SearchLimits::unlimited())
            .unwrap();
        let (earliest, earliest_accounting) = plan
            .shortest_window(haystack, window, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(selected, Some((1, 5)));
        assert_eq!(earliest, Some(2));
        assert!(
            plan.is_match_window_value(haystack, window, SearchLimits::unlimited())
                .unwrap()
        );
        assert_eq!(
            selected_accounting.operation_id,
            GENERAL_SEARCH_OPERATION_ID
        );
        assert_eq!(
            earliest_accounting.operation_id,
            GENERAL_SHORTEST_SEARCH_OPERATION_ID
        );
        assert_eq!(selected_accounting.window_bytes, 4);
        assert_eq!(earliest_accounting.window_bytes, 4);
    }

    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "small exhaustive fixtures have fixed lengths and bounded radix arithmetic"
    )]
    fn generalized_value_existence_matches_byte_oracle_in_every_window() {
        let cases = [
            (
                generalized_plan(
                    b"a",
                    [(b'a', b'b')].into_iter(),
                    b"c",
                    SearchRunMinimum::Zero,
                ),
                r"a[ab]*c",
            ),
            (
                generalized_plan(
                    b"a",
                    [(b'a', b'b')].into_iter(),
                    b"c",
                    SearchRunMinimum::One,
                ),
                r"a[ab]+c",
            ),
            (
                generalized_plan(
                    b"a",
                    [(b'b', b'c')].into_iter(),
                    b"",
                    SearchRunMinimum::Zero,
                ),
                r"a[bc]*",
            ),
            (
                generalized_plan(b"a", [(b'b', b'c')].into_iter(), b"", SearchRunMinimum::One),
                r"a[bc]+",
            ),
        ];
        let alphabet = b"abcx";
        for (plan, pattern) in cases {
            let oracle = RegexBuilder::new(pattern).unicode(false).build().unwrap();
            for length in 0_usize..=5 {
                let haystack_count = alphabet.len().pow(u32::try_from(length).unwrap());
                for mut ordinal in 0..haystack_count {
                    let mut haystack = vec![0_u8; length];
                    for byte in &mut haystack {
                        *byte = alphabet[ordinal % alphabet.len()];
                        ordinal /= alphabet.len();
                    }
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let expected = oracle.find(&haystack[start..end]).map(|matched| {
                                (start + matched.start(), start + matched.end())
                            });
                            let expected_shortest = oracle
                                .shortest_match(&haystack[start..end])
                                .map(|relative_end| start + relative_end);
                            assert_eq!(
                                plan.find_window_value(
                                    &haystack,
                                    Window::new(start, end),
                                    SearchLimits::unlimited(),
                                )
                                .unwrap(),
                                expected,
                                "selected pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                            );
                            assert_eq!(
                                plan.is_match_window_value(
                                    &haystack,
                                    Window::new(start, end),
                                    SearchLimits::unlimited(),
                                )
                                .unwrap(),
                                expected.is_some(),
                                "pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                            );
                            assert_eq!(
                                plan.shortest_window_value(
                                    &haystack,
                                    Window::new(start, end),
                                    SearchLimits::unlimited(),
                                )
                                .unwrap(),
                                expected_shortest,
                                "shortest pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        clippy::too_many_lines,
        reason = "one matrix keeps exhaustive scalar/dispatched parity and fixed scanner-boundary corpora adjacent"
    )]
    fn guarded_ordinary_full_values_match_scalar_and_dispatched_oracles() {
        let dispatch = SimdDispatchContext::capture();
        let guarded_cases = [
            (
                [(b'A', b'B')],
                r"\b[A-B]+T\b",
                b"ABT0!\xFF".as_slice(),
            ),
            (
                [(b'A', b'T')],
                r"\b[A-T]+T\b",
                b"AMT0!\x80".as_slice(),
            ),
        ];
        for (ranges, pattern, alphabet) in guarded_cases {
            let scalar = LiteralClassRunSearchPlan::build(
                b"",
                ranges.into_iter(),
                b"T",
                SearchRunMinimum::One,
                BoundarySemantics::CompleteAsciiWordRun,
                BuildLimits::unlimited(),
            )
            .unwrap();
            let dispatched = LiteralClassRunSearchPlan::build_with_dispatch(
                dispatch,
                b"",
                ranges.into_iter(),
                b"T",
                SearchRunMinimum::One,
                BoundarySemantics::CompleteAsciiWordRun,
                BuildLimits::unlimited(),
            )
            .unwrap();
            assert!(scalar.ascii_scanner.is_none());
            assert!(dispatched.ascii_scanner.is_some());
            let oracle = RegexBuilder::new(pattern).unicode(false).build().unwrap();
            for length in 0_usize..=5 {
                let haystack_count = alphabet.len().pow(u32::try_from(length).unwrap());
                for mut ordinal in 0..haystack_count {
                    let mut haystack = vec![0_u8; length];
                    for byte in &mut haystack {
                        *byte = alphabet[ordinal % alphabet.len()];
                        ordinal /= alphabet.len();
                    }
                    let expected = oracle
                        .find(&haystack)
                        .map(|matched| (matched.start(), matched.end()));
                    for plan in [&scalar, &dispatched] {
                        assert_eq!(
                            plan.find_ascii_word_suffix_full_ordinary_value(&haystack)
                                .unwrap(),
                            expected,
                            "selected pattern={pattern:?} haystack={haystack:?}"
                        );
                        assert_eq!(
                            plan.find(&haystack, SearchLimits::unlimited()).unwrap().0,
                            expected,
                            "accounted pattern={pattern:?} haystack={haystack:?}"
                        );
                    }
                }
            }
        }

        let guarded_scalar = LiteralClassRunSearchPlan::build(
            b"",
            [(b'A', b'T')].into_iter(),
            b"T",
            SearchRunMinimum::One,
            BoundarySemantics::CompleteAsciiWordRun,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let guarded_dispatched = LiteralClassRunSearchPlan::build_with_dispatch(
            dispatch,
            b"",
            [(b'A', b'T')].into_iter(),
            b"T",
            SearchRunMinimum::One,
            BoundarySemantics::CompleteAsciiWordRun,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let mut guarded_haystack = b"0AATX!\xFF".to_vec();
        guarded_haystack.extend(core::iter::repeat_n(b'A', ASCII_WIDE_BYTES * 3 + 7));
        guarded_haystack.extend_from_slice(b"TT\x80");
        let guarded_oracle = RegexBuilder::new(r"\b[A-T]+T\b")
            .unicode(false)
            .build()
            .unwrap();
        let guarded_expected = guarded_oracle
            .find(&guarded_haystack)
            .map(|matched| (matched.start(), matched.end()));
        for plan in [&guarded_scalar, &guarded_dispatched] {
            assert_eq!(
                plan.find_ascii_word_suffix_full_ordinary_value(&guarded_haystack)
                    .unwrap(),
                guarded_expected
            );
        }
    }

    #[test]
    fn unicode_all_non_ascii_search_matches_upstream_on_valid_and_invalid_utf8() {
        let plan = unicode_generalized_plan();
        let oracle = RegexBuilder::new(r"a[^z\r\n]*z").build().unwrap();
        let haystacks = [
            b"".as_slice(),
            b"abz",
            "--aé文z--".as_bytes(),
            b"a\x80z--abz",
            b"a\xC0\xAFz--aokz",
            b"a\xED\xA0\x80z--aokz",
            b"a\xF4\x90\x80\x80z--aokz",
            b"a\xF0\x9F\x92z--aokz",
            b"aaaz--a\xFFz--abz",
        ];
        for haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = Window::new(start, end);
                    let expected = oracle
                        .find(&haystack[start..end])
                        .map(|matched| (start + matched.start(), start + matched.end()));
                    let expected_shortest = oracle
                        .shortest_match(&haystack[start..end])
                        .map(|matched_end| start + matched_end);
                    assert_eq!(
                        plan.find_window(haystack, window, SearchLimits::unlimited())
                            .unwrap()
                            .0,
                        expected,
                        "haystack={haystack:?} window={start}..{end}"
                    );
                    assert_eq!(
                        plan.find_window_value(haystack, window, SearchLimits::unlimited())
                            .unwrap(),
                        expected,
                        "value haystack={haystack:?} window={start}..{end}"
                    );
                    assert_eq!(
                        plan.shortest_window(haystack, window, SearchLimits::unlimited())
                            .unwrap()
                            .0,
                        expected_shortest,
                        "shortest haystack={haystack:?} window={start}..{end}"
                    );
                    assert_eq!(
                        plan.shortest_window_value(
                            haystack,
                            window,
                            SearchLimits::unlimited(),
                        )
                        .unwrap(),
                        expected_shortest,
                        "shortest value haystack={haystack:?} window={start}..{end}"
                    );
                    assert_eq!(
                        plan.is_match_window_value(haystack, window, SearchLimits::unlimited())
                            .unwrap(),
                        expected.is_some(),
                        "exists haystack={haystack:?} window={start}..{end}"
                    );
                }
            }
        }
        assert_eq!(plan.plan_id(), UNICODE_ALL_NON_ASCII_SEARCH_PLAN_ID);
    }

    #[test]
    fn unicode_all_non_ascii_mixed_corridors_preserve_semantics_and_bounds() {
        let dispatch = SimdDispatchContext::capture();
        let plan = LiteralClassRunSearchPlan::build_unicode_all_non_ascii_with_dispatch(
            dispatch,
            b"a",
            [
                ('\0', '\u{9}'),
                ('\u{B}', '\u{C}'),
                ('\u{E}', 'y'),
                ('{', char::MAX),
            ]
            .into_iter(),
            b"z",
            SearchRunMinimum::Zero,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let oracle = RegexBuilder::new(r"a[^z\r\n]*z").build().unwrap();
        let scalar_build = unicode_generalized_plan().build_accounting();
        let build = plan.build_accounting();
        let expected_scanner_work = if dispatch.capabilities().usable().contains(Feature::ArmSve) {
            SIMD_RUN_SCANNER_BUILD_WORK
        } else {
            SIMD_FIXED_CLASSIFIER_BUILD_WORK
        };
        assert_eq!(
            build.work_upper_bound,
            scalar_build
                .work_upper_bound
                .checked_add(expected_scanner_work)
                .unwrap()
        );
        assert_eq!(build.persistent_bytes, scalar_build.persistent_bytes);
        assert_eq!(build.peak_bytes, scalar_build.peak_bytes);
        match plan.ascii_scanner {
            Some(AsciiClassScanner::Run(scanner)) => {
                assert!(dispatch.capabilities().usable().contains(Feature::ArmSve));
                assert!(!scanner.selection().variant_id.contains("match16"));
                if scanner.selection().variant_id.contains("sve2") {
                    assert!(scanner.selection().variant_id.contains("complement16"));
                }
            }
            Some(AsciiClassScanner::Fixed(_)) => {
                assert!(!dispatch.capabilities().usable().contains(Feature::ArmSve));
            }
            None => panic!("a dispatched Unicode plan retains one ASCII scanner"),
        }

        let mut early_then_long_ascii = b"--a".to_vec();
        early_then_long_ascii.extend_from_slice("🦀".as_bytes());
        early_then_long_ascii.extend(core::iter::repeat_n(b'q', 4_093));
        early_then_long_ascii.extend_from_slice(b"z--");

        let mut alternating_short_corridors = b"--a".to_vec();
        for _ in 0..64 {
            alternating_short_corridors.extend_from_slice("é".as_bytes());
            alternating_short_corridors.push(b'q');
        }
        alternating_short_corridors.extend_from_slice(b"z--");

        let mut invalid_then_later_anchor = b"--a".to_vec();
        invalid_then_later_anchor.extend_from_slice("€".as_bytes());
        invalid_then_later_anchor.extend(core::iter::repeat_n(b'x', 97));
        invalid_then_later_anchor.extend_from_slice(b"\xED\xA0\x80z--aokz--");

        for haystack in [
            early_then_long_ascii.as_slice(),
            alternating_short_corridors.as_slice(),
            invalid_then_later_anchor.as_slice(),
        ] {
            let expected = oracle
                .find(haystack)
                .map(|matched| (matched.start(), matched.end()));
            let (actual, accounting) = plan.find(haystack, SearchLimits::unlimited()).unwrap();
            let upper = plan.search_upper_bounds(haystack.len()).unwrap();
            assert_eq!(actual, expected, "haystack={haystack:?}");
            assert!(
                accounting.classifications <= upper.classifications,
                "haystack={haystack:?} actual={} upper={}",
                accounting.classifications,
                upper.classifications
            );
            assert!(accounting.source_reads <= accounting.source_reads_upper_bound);
            assert!(u64::try_from(accounting.work).unwrap() <= accounting.work_upper_bound);
        }
    }

    #[test]
    fn bounded_preferred_anchor_matches_every_projection_exhaustively() {
        let cases = [
            (
                BoundedLiteralClassRunPlan::build(
                    b"QQ",
                    [(b'0', b'0')].into_iter(),
                    b"aa",
                    1,
                    2,
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                Anchor::Prefix,
                r"QQ0{1,2}aa",
            ),
            (
                BoundedLiteralClassRunPlan::build(
                    b"aa",
                    [(b'0', b'0')].into_iter(),
                    b"QQ",
                    0,
                    2,
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                Anchor::Suffix,
                r"aa0{0,2}QQ",
            ),
        ];
        let alphabet = b"aQ0x";
        for (plan, expected_anchor, pattern) in cases {
            assert_eq!(plan.preferred_anchor, expected_anchor);
            let oracle = RegexBuilder::new(pattern).unicode(false).build().unwrap();
            let mut witnessed_runs = [false; 3];
            for length in 0_usize..=6 {
                let haystack_count = alphabet.len().pow(u32::try_from(length).unwrap());
                for mut ordinal in 0..haystack_count {
                    let mut haystack = vec![0_u8; length];
                    for byte in &mut haystack {
                        *byte = alphabet[ordinal % alphabet.len()];
                        ordinal /= alphabet.len();
                    }
                    for (start, end) in assert_bounded_orders_are_isomorphic(&plan, &haystack) {
                        let run_len = end - start - plan.prefix().len() - plan.suffix().len();
                        witnessed_runs[run_len] = true;
                    }
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let window = Window::new(start, end);
                            let expected = oracle
                                .find(&haystack[start..end])
                                .map(|matched| (start + matched.start(), start + matched.end()));
                            let expected_end = oracle
                                .shortest_match(&haystack[start..end])
                                .map(|relative| start + relative);
                            assert_eq!(
                                plan.find_window(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap()
                                .0,
                                expected,
                                "selected pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                            );
                            assert_eq!(
                                plan.find_window_value(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap(),
                                expected,
                                "value pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                            );
                            assert_eq!(
                                plan.shortest_window(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap()
                                .0,
                                expected_end,
                                "shortest pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                            );
                            assert_eq!(
                                plan.shortest_window_value(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap(),
                                expected_end,
                                "shortest value pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                            );
                            assert_eq!(
                                plan.is_match_window_value(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap(),
                                expected.is_some(),
                                "exists pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                            );
                        }
                    }
                }
            }
            if plan.minimum == 0 {
                assert_eq!(witnessed_runs, [true, true, true]);
            } else {
                assert_eq!(witnessed_runs, [false, true, true]);
            }
        }
    }

    #[test]
    fn bounded_non_crossing_order_includes_zero_and_self_overlapping_barriers() {
        let overlapping = BoundedLiteralClassRunPlan::build(
            b"aa",
            [(b'0', b'1')].into_iter(),
            b"aa",
            0,
            0,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(overlapping.preferred_anchor, Anchor::Suffix);
        assert_eq!(
            assert_bounded_orders_are_isomorphic(&overlapping, b"aaaaa"),
            vec![(0, 4), (1, 5)]
        );
        assert_eq!(
            overlapping
                .find(b"aaaaa", SearchLimits::unlimited())
                .unwrap()
                .0,
            Some((0, 4))
        );
        assert_eq!(
            overlapping
                .shortest_window(
                    b"aaaaa",
                    Window::full(b"aaaaa"),
                    SearchLimits::unlimited(),
                )
                .unwrap()
                .0,
            Some(4)
        );

        let cases = [
            (
                BoundedLiteralClassRunPlan::build(
                    b"aa",
                    [(b'0', b'0')].into_iter(),
                    b"QQ",
                    0,
                    2,
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                Anchor::Suffix,
                r"aa0{0,2}QQ",
                [b"aa00QQ-aa0QQ".as_slice(), b"aa0QQ-aa00QQ".as_slice()],
            ),
            (
                BoundedLiteralClassRunPlan::build(
                    b"QQ",
                    [(b'0', b'0')].into_iter(),
                    b"aa",
                    0,
                    2,
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                Anchor::Prefix,
                r"QQ0{0,2}aa",
                [b"QQ00aa-QQ0aa".as_slice(), b"QQ0aa-QQ00aa".as_slice()],
            ),
        ];
        for (plan, expected_anchor, pattern, haystacks) in cases {
            assert_eq!(plan.preferred_anchor, expected_anchor);
            let oracle = RegexBuilder::new(pattern).unicode(false).build().unwrap();
            for haystack in haystacks {
                let spans = assert_bounded_orders_are_isomorphic(&plan, haystack);
                assert_eq!(spans.len(), 2, "pattern={pattern:?}");
                let expected = oracle
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end()));
                let expected_end = oracle.shortest_match(haystack);
                assert_eq!(
                    plan.find(haystack, SearchLimits::unlimited()).unwrap().0,
                    expected
                );
                assert_eq!(
                    plan.shortest_window(
                        haystack,
                        Window::full(haystack),
                        SearchLimits::unlimited(),
                    )
                    .unwrap()
                    .0,
                    expected_end
                );
            }
        }
    }

    #[test]
    fn bounded_preferred_anchor_refuses_before_each_unproved_candidate() {
        let prefix_preferred = BoundedLiteralClassRunPlan::build(
            b"QZ",
            [(b'0', b'0')].into_iter(),
            b"aa",
            0,
            2,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(prefix_preferred.preferred_anchor, Anchor::Prefix);
        assert_bounded_projection_limit_parity(&prefix_preferred, b"QZx--QZ0aa");

        let suffix_preferred = BoundedLiteralClassRunPlan::build(
            b"aa",
            [(b'0', b'0')].into_iter(),
            b"QZ",
            0,
            2,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(suffix_preferred.preferred_anchor, Anchor::Suffix);
        assert_bounded_projection_limit_parity(&suffix_preferred, b"xxQZ--aa0QZ");
    }

    #[test]
    fn bounded_skewed_anchor_accounting_is_linear_in_one_rare_scan() {
        let cases = [
            (
                BoundedLiteralClassRunPlan::build(
                    b"aaaaaaaa",
                    [(b'0', b'0')].into_iter(),
                    b"QZ",
                    0,
                    4,
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                Anchor::Suffix,
            ),
            (
                BoundedLiteralClassRunPlan::build(
                    b"QZ",
                    [(b'0', b'0')].into_iter(),
                    b"aaaaaaaa",
                    0,
                    4,
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                Anchor::Prefix,
            ),
        ];
        for (plan, expected_anchor) in &cases {
            assert_eq!(plan.preferred_anchor, *expected_anchor);
            let mut accounting = Vec::new();
            for length in [4_096, 8_192] {
                let haystack = vec![b'a'; length];
                let (matched, actual) = plan
                    .find(&haystack, SearchLimits::unlimited())
                    .unwrap();
                assert_eq!(matched, None);
                assert_eq!(actual.candidate_visits, 0);
                assert_eq!(actual.finder_calls, 1);
                assert_eq!(actual.classifications, 0);
                assert_eq!(actual.literal_comparisons, 0);
                assert_eq!(actual.source_reads, length);
                assert!(actual.source_reads <= actual.source_reads_upper_bound);
                accounting.push(actual);
            }
            assert_eq!(
                accounting[1].work - accounting[0].work,
                4_096 * FINDER_SCAN_WORK
            );
        }

        let suffix_preferred = &cases[0].0;
        let mut late_suffix = vec![b'a'; 4_096];
        late_suffix.extend_from_slice(b"0QZ");
        let (selected, suffix_accounting) = suffix_preferred
            .find(&late_suffix, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(selected, Some((4_088, 4_099)));
        assert_eq!(suffix_accounting.candidate_visits, 1);
        assert_eq!(suffix_accounting.finder_calls, 1);
        assert_eq!(suffix_accounting.literal_comparisons, 8);

        let prefix_preferred = &cases[1].0;
        let mut late_prefix = vec![b'a'; 4_096];
        late_prefix.extend_from_slice(b"QZ0aaaaaaaa");
        let (selected, prefix_accounting) = prefix_preferred
            .find(&late_prefix, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(selected, Some((4_096, 4_107)));
        assert_eq!(prefix_accounting.candidate_visits, 1);
        assert_eq!(prefix_accounting.finder_calls, 1);
        assert_eq!(prefix_accounting.literal_comparisons, 8);
    }

    #[test]
    fn bounded_primitive_period_proof_is_exhaustive_and_exactly_charged() {
        for (sample, expected_period, expected_work) in [
            (b"a".as_slice(), 1, 0),
            (b"ab".as_slice(), 2, 1),
            (b"aaaa".as_slice(), 1, 3),
            (b"abab".as_slice(), 2, 3),
            (b"ababa".as_slice(), 2, 4),
            (b"abcab".as_slice(), 3, 4),
            (b"aaab".as_slice(), 4, 6),
            (b"abcdabce".as_slice(), 8, 10),
        ] {
            let mut actual = DirectBuildAttemptActual::default();
            let mut work = BuildWork::new(expected_work, &mut actual);
            assert_eq!(
                bounded_sample_primitive_period(sample, &mut work).unwrap(),
                expected_period
            );
            assert_eq!(work.used, expected_work);
            assert_eq!(actual.work, u64::try_from(expected_work).unwrap());

            for limit in 0..expected_work {
                let mut actual = DirectBuildAttemptActual::default();
                let mut work = BuildWork::new(limit, &mut actual);
                assert!(matches!(
                    bounded_sample_primitive_period(sample, &mut work),
                    Err(BuildError::WorkLimit { needed, limit: actual_limit })
                        if needed == limit + 1 && actual_limit == limit
                ));
                assert_eq!(work.used, limit);
                assert_eq!(actual.work, u64::try_from(limit).unwrap());
            }
        }

        for length in 1..=8 {
            for bits in 0..(1_usize << length) {
                let sample: Vec<u8> = (0..length)
                    .map(|index| {
                        if bits & (1_usize << index) == 0 {
                            b'a'
                        } else {
                            b'b'
                        }
                    })
                    .collect();
                let expected = (1..sample.len())
                    .find(|&period| sample[period..] == sample[..sample.len() - period])
                    .unwrap_or(sample.len());
                let mut actual = DirectBuildAttemptActual::default();
                let mut work = BuildWork::new(usize::MAX, &mut actual);
                assert_eq!(
                    bounded_sample_primitive_period(&sample, &mut work).unwrap(),
                    expected,
                    "sample={sample:?}"
                );
            }
        }

        let bounded_prefix = b"ab".repeat(150);
        let mut different_tail = bounded_prefix.clone();
        different_tail[usize::from(u8::MAX)..].fill(b'z');
        let (prefix_score, prefix_work) = {
            let mut actual = DirectBuildAttemptActual::default();
            let mut work = BuildWork::new(usize::MAX, &mut actual);
            let score = (
                bounded_anchor_frequency_score(&bounded_prefix, &mut work).unwrap(),
                bounded_anchor_overlap_score(&bounded_prefix, &mut work).unwrap(),
            );
            (score, work.used)
        };
        let (tail_score, tail_work) = {
            let mut actual = DirectBuildAttemptActual::default();
            let mut work = BuildWork::new(usize::MAX, &mut actual);
            let score = (
                bounded_anchor_frequency_score(&different_tail, &mut work).unwrap(),
                bounded_anchor_overlap_score(&different_tail, &mut work).unwrap(),
            );
            (score, work.used)
        };
        assert_eq!(prefix_score, tail_score);
        assert_eq!(prefix_score.1.primitive_period, 2);
        assert_eq!(prefix_work, tail_work);
        assert_eq!(prefix_work, 510);

        let full_period = |literal: &[u8]| {
            (1..literal.len())
                .find(|&period| literal[period..] == literal[..literal.len() - period])
                .unwrap_or(literal.len())
        };
        assert_eq!(full_period(&bounded_prefix), 2);
        assert!(full_period(&different_tail) > prefix_score.1.primitive_period);
        for literal in [&bounded_prefix, &different_tail] {
            assert!(full_period(literal) >= prefix_score.1.primitive_period);
        }

        for (prefix, suffix) in [
            (bounded_prefix.as_slice(), different_tail.as_slice()),
            (different_tail.as_slice(), bounded_prefix.as_slice()),
        ] {
            let mut actual = DirectBuildAttemptActual::default();
            let mut work = BuildWork::new(usize::MAX, &mut actual);
            assert_eq!(
                bounded_preferred_anchor(prefix, suffix, &mut work).unwrap(),
                Anchor::Suffix
            );
            assert_eq!(work.used, 1_024);
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one test keeps the score order, symmetric routing, receipts, and dense-candidate proof adjacent"
    )]
    fn bounded_periodic_score_ties_prefer_smaller_repetition_factor_symmetrically() {
        let periodic = b"abababab";
        let unbordered = b"abaaaabb";
        let mut periodic_actual = DirectBuildAttemptActual::default();
        let mut periodic_work = BuildWork::new(usize::MAX, &mut periodic_actual);
        let periodic_frequency =
            bounded_anchor_frequency_score(periodic, &mut periodic_work).unwrap();
        let periodic_overlap = bounded_anchor_overlap_score(periodic, &mut periodic_work).unwrap();
        let mut unbordered_actual = DirectBuildAttemptActual::default();
        let mut unbordered_work = BuildWork::new(usize::MAX, &mut unbordered_actual);
        let unbordered_frequency =
            bounded_anchor_frequency_score(unbordered, &mut unbordered_work).unwrap();
        let unbordered_overlap =
            bounded_anchor_overlap_score(unbordered, &mut unbordered_work).unwrap();
        assert_eq!(periodic_frequency, unbordered_frequency);
        assert_eq!(periodic_overlap.primitive_period, 2);
        assert_eq!(unbordered_overlap.primitive_period, unbordered.len());

        let unbordered_suffix = BoundedLiteralClassRunPlan::build(
            periodic,
            [(b'0', b'0')].into_iter(),
            unbordered,
            0,
            0,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let unbordered_prefix = BoundedLiteralClassRunPlan::build(
            unbordered,
            [(b'0', b'0')].into_iter(),
            periodic,
            0,
            0,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(unbordered_suffix.preferred_anchor, Anchor::Suffix);
        assert_eq!(unbordered_prefix.preferred_anchor, Anchor::Prefix);
        assert_eq!(
            unbordered_suffix.build_accounting(),
            unbordered_prefix.build_accounting()
        );

        let primitive_root_prefix = BoundedLiteralClassRunPlan::build(
            b"ab",
            [(b'0', b'0')].into_iter(),
            periodic,
            0,
            0,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let primitive_root_suffix = BoundedLiteralClassRunPlan::build(
            periodic,
            [(b'0', b'0')].into_iter(),
            b"ab",
            0,
            0,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(primitive_root_prefix.preferred_anchor, Anchor::Prefix);
        assert_eq!(primitive_root_suffix.preferred_anchor, Anchor::Suffix);
        assert_eq!(
            primitive_root_prefix.build_accounting().work_upper_bound,
            primitive_root_suffix.build_accounting().work_upper_bound
        );

        let longer_unbordered_suffix = BoundedLiteralClassRunPlan::build(
            b"ab",
            [(b'0', b'0')].into_iter(),
            unbordered,
            0,
            0,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let longer_unbordered_prefix = BoundedLiteralClassRunPlan::build(
            unbordered,
            [(b'0', b'0')].into_iter(),
            b"ab",
            0,
            0,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(longer_unbordered_suffix.preferred_anchor, Anchor::Suffix);
        assert_eq!(longer_unbordered_prefix.preferred_anchor, Anchor::Prefix);
        assert_eq!(
            longer_unbordered_suffix
                .build_accounting()
                .work_upper_bound,
            longer_unbordered_prefix
                .build_accounting()
                .work_upper_bound
        );

        for (prefix, suffix, expected_anchor) in [
            (b"QZ".as_slice(), b"aaaaaaaa".as_slice(), Anchor::Prefix),
            (b"aaaaaaaa".as_slice(), b"QZ".as_slice(), Anchor::Suffix),
        ] {
            let mut actual = DirectBuildAttemptActual::default();
            let mut work = BuildWork::new(usize::MAX, &mut actual);
            assert_eq!(
                bounded_preferred_anchor(prefix, suffix, &mut work).unwrap(),
                expected_anchor
            );
            assert_eq!(work.used, prefix.len() + suffix.len());
        }

        let haystack = b"ab".repeat(2_048);
        for plan in [&unbordered_suffix, &unbordered_prefix] {
            let (matched, accounting) = plan
                .find(&haystack, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(matched, None);
            assert_eq!(accounting.candidate_visits, 0);
            assert_eq!(accounting.finder_calls, 1);
            assert!(accounting.source_reads <= accounting.source_reads_upper_bound);
        }

        for (prefix, suffix, expected_anchor) in [
            (periodic.as_slice(), unbordered.as_slice(), Anchor::Suffix),
            (unbordered.as_slice(), periodic.as_slice(), Anchor::Prefix),
        ] {
            let baseline = BoundedLiteralClassRunPlan::build(
                prefix,
                [(b'0', b'0')].into_iter(),
                suffix,
                0,
                0,
                BuildLimits::unlimited(),
            )
            .unwrap()
            .build_accounting();
            let exact = BuildLimits {
                max_literal_bytes: baseline.literal_bytes,
                max_class_ranges: baseline.class_ranges,
                max_class_members: baseline.class_members,
                max_build_work: baseline.work_upper_bound,
                max_scratch_bytes: baseline.scratch_bytes,
                max_persistent_bytes: baseline.persistent_bytes,
                max_peak_bytes: baseline.peak_bytes,
            };
            let exact_plan = BoundedLiteralClassRunPlan::build(
                prefix,
                [(b'0', b'0')].into_iter(),
                suffix,
                0,
                0,
                exact,
            )
            .unwrap();
            assert_eq!(exact_plan.preferred_anchor, expected_anchor);
            assert_eq!(exact_plan.build_accounting(), baseline);

            let below = BuildLimits {
                max_build_work: baseline.work_upper_bound - 1,
                ..exact
            };
            assert!(matches!(
                BoundedLiteralClassRunPlan::build(
                    prefix,
                    [(b'0', b'0')].into_iter(),
                    suffix,
                    0,
                    0,
                    below,
                ),
                Err(BuildError::WorkLimit { needed, limit })
                    if needed == baseline.work_upper_bound
                        && limit == baseline.work_upper_bound - 1
            ));
        }
    }

    #[test]
    fn bounded_native_cost_gate_uses_suffix_horizon_and_strict_period() {
        let prefix = BoundedAnchorSelection {
            preferred: Anchor::Prefix,
            strict_full_width_repetition: None,
            strict_full_width_opposite_period: None,
        };
        let suffix = BoundedAnchorSelection {
            preferred: Anchor::Suffix,
            strict_full_width_repetition: None,
            strict_full_width_opposite_period: None,
        };
        let sustained = 2 * ASCII_WIDE_BYTES;
        assert!(!bounded_native_cost_admitted(sustained - 2, suffix, true).unwrap());
        assert!(bounded_native_cost_admitted(sustained - 1, suffix, true).unwrap());
        assert!(!bounded_native_cost_admitted(sustained - 1, prefix, true).unwrap());
        assert!(!bounded_native_cost_admitted(usize::MAX, prefix, true).unwrap());
        assert!(!bounded_native_cost_admitted(usize::MAX, prefix, false).unwrap());
        assert!(!bounded_native_cost_admitted(usize::MAX, suffix, false).unwrap());

        for anchor in [Anchor::Prefix, Anchor::Suffix] {
            let strict = BoundedAnchorSelection {
                preferred: anchor,
                strict_full_width_repetition: Some(anchor),
                strict_full_width_opposite_period: Some(2),
            };
            assert!(bounded_native_cost_admitted(0, strict, false).unwrap());
        }
        let uniform_prefix = BoundedAnchorSelection {
            preferred: Anchor::Prefix,
            strict_full_width_repetition: Some(Anchor::Prefix),
            strict_full_width_opposite_period: Some(1),
        };
        assert!(!bounded_native_cost_admitted(usize::MAX, uniform_prefix, true).unwrap());
    }

    #[test]
    fn bounded_native_cost_gate_reads_actual_and_static_vector_receipts() {
        let set = AsciiByteSet::from_words([1_u64 << u32::from(b'0'), 0]);
        let fixed = AsciiClassScanner::Fixed(AsciiByteSetClassifier::new(set));
        let run = AsciiClassScanner::Run(AsciiByteSetRunScanner::new(set));
        // In compiler-static profiles these public accessors reconstruct the
        // compiler-fixed receipts rather than reading retained runtime fields.
        for scanner in [&fixed, &run] {
            let expected = match scanner {
                AsciiClassScanner::Fixed(classifier) => {
                    !matches!(classifier.selection().wide().vector, VectorKind::Scalar)
                }
                AsciiClassScanner::Run(scanner) => {
                    !matches!(scanner.selection().vector, VectorKind::Scalar)
                }
            };
            assert_eq!(bounded_ascii_scanner_has_vector(Some(scanner)), expected);
        }
        assert!(!bounded_ascii_scanner_has_vector(None));
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn bounded_native_cost_gate_rejects_retained_scalar_scanners() {
        let set = AsciiByteSet::from_words([1_u64 << u32::from(b'0'), 0]);
        let fixed = AsciiClassScanner::Fixed(
            AsciiByteSetClassifier::with_policy(set, DispatchPolicy::Portable).unwrap(),
        );
        let run = AsciiClassScanner::Run(
            AsciiByteSetRunScanner::with_policy(set, DispatchPolicy::Portable).unwrap(),
        );
        let selection = BoundedAnchorSelection {
            preferred: Anchor::Suffix,
            strict_full_width_repetition: None,
            strict_full_width_opposite_period: None,
        };
        for scanner in [&fixed, &run] {
            assert!(!bounded_ascii_scanner_has_vector(Some(scanner)));
            assert!(!bounded_native_cost_admitted(
                usize::MAX,
                selection,
                bounded_ascii_scanner_has_vector(Some(scanner)),
            )
            .unwrap());
        }
    }

    #[test]
    fn bounded_sampled_period_cannot_override_horizon_past_its_proof_width() {
        let mut unbordered_sample = vec![b'a'; usize::from(u8::MAX)];
        unbordered_sample[0] = b'Q';
        unbordered_sample[1] = b'Z';
        let mut prefix = unbordered_sample.clone();
        prefix.extend_from_slice(&unbordered_sample);

        let mut suffix = Vec::with_capacity(usize::from(u8::MAX) + 1);
        for index in 0..usize::from(u8::MAX) {
            suffix.push(if index & 1 == 0 { b'Q' } else { b'Z' });
        }
        suffix.push(b'U');

        let mut actual = DirectBuildAttemptActual::default();
        let mut work = BuildWork::new(usize::MAX, &mut actual);
        assert_eq!(
            bounded_preferred_anchor(&prefix, &suffix, &mut work).unwrap(),
            Anchor::Prefix,
            "legacy preference still uses the bounded sample"
        );

        let mut actual = DirectBuildAttemptActual::default();
        let mut work = BuildWork::new(usize::MAX, &mut actual);
        let selection = bounded_anchor_selection(
            &prefix,
            &suffix,
            &mut work,
            BoundedAnchorScoreMode::AdmissionProof,
        )
        .unwrap();
        assert_eq!(selection.preferred, Anchor::Prefix);
        assert_eq!(selection.strict_full_width_repetition, None);
        assert_eq!(selection.strict_full_width_opposite_period, None);

        let mut actual = DirectBuildAttemptActual::default();
        let mut work = BuildWork::new(usize::MAX, &mut actual);
        let full_prefix_period = bounded_sample_primitive_period(&prefix, &mut work).unwrap();
        let full_suffix_period = bounded_sample_primitive_period(&suffix, &mut work).unwrap();
        assert_eq!(full_prefix_period, usize::from(u8::MAX));
        assert_eq!(full_suffix_period, usize::from(u8::MAX) + 1);
        assert!(
            suffix.len() * full_prefix_period < prefix.len() * full_suffix_period,
            "the bytes beyond the sample invert the full-width preference"
        );
        assert!(!bounded_native_cost_admitted(0, selection, true).unwrap());

        assert!(
            BoundedLiteralClassRunPlan::build_with_dispatch_if_admitted(
                SimdDispatchContext::capture(),
                &prefix,
                [(b'0', b'0')].into_iter(),
                &suffix,
                0,
                0,
                BuildLimits::unlimited(),
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one matrix keeps semantic decline, exact threshold, period override, and resource propagation adjacent"
    )]
    fn bounded_admitted_build_declines_before_allocation_and_preserves_resource_errors() {
        let ascii = |prefix: &[u8], suffix: &[u8], maximum, limits| {
            BoundedLiteralClassRunPlan::build_with_dispatch_if_admitted(
                SimdDispatchContext::capture(),
                prefix,
                [(b'0', b'0')].into_iter(),
                suffix,
                0,
                maximum,
                limits,
            )
        };
        let has_vector_scanner = bounded_test_auto_scanner_has_vector();

        let prefix_selected = b"Q\x92";
        assert!(ascii(
            prefix_selected,
            b"U",
            2 * ASCII_WIDE_BYTES - 1,
            BuildLimits::unlimited(),
        )
        .unwrap()
        .is_none());
        let threshold_plan = ascii(
            prefix_selected,
            b"U",
            2 * ASCII_WIDE_BYTES,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert!(threshold_plan.is_none());

        let wide_unbordered_suffix = b"abaaaabb";
        assert!(ascii(
            b"QZ",
            wide_unbordered_suffix,
            2 * ASCII_WIDE_BYTES,
            BuildLimits::unlimited(),
        )
        .unwrap()
        .is_none());
        assert!(
            ascii(
                b"QZ",
                wide_unbordered_suffix,
                usize::MAX,
                BuildLimits::unlimited(),
            )
            .unwrap()
            .is_none()
        );

        let unbordered_prefix = b"abaaaabb";
        assert!(ascii(
            unbordered_prefix,
            b"QZ",
            2 * ASCII_WIDE_BYTES - 2,
            BuildLimits::unlimited(),
        )
        .unwrap()
        .is_none());
        let suffix_threshold_plan = ascii(
            unbordered_prefix,
            b"QZ",
            2 * ASCII_WIDE_BYTES - 1,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(suffix_threshold_plan.is_some(), has_vector_scanner);
        if let Some(plan) = suffix_threshold_plan {
            assert_eq!(plan.preferred_anchor, Anchor::Suffix);
        }

        assert!(
            ascii(
                b"QZ",
                b"aaaaaaaa",
                usize::MAX,
                BuildLimits::unlimited(),
            )
            .unwrap()
            .is_none(),
            "a uniform suffix must not force prefix-driven native search"
        );
        for (prefix, suffix, expected_anchor) in [
            (b"abaaaabb".as_slice(), b"abababab".as_slice(), Anchor::Prefix),
            (b"abababab".as_slice(), b"abaaaabb".as_slice(), Anchor::Suffix),
            (b"aaaaaaaa".as_slice(), b"QZ".as_slice(), Anchor::Suffix),
        ] {
            let plan = ascii(prefix, suffix, 0, BuildLimits::unlimited())
                .unwrap()
                .expect("strict repetition improvement overrides the horizon");
            assert_eq!(plan.preferred_anchor, expected_anchor);
        }

        let without_ascii_scanner =
            BoundedLiteralClassRunPlan::build_with_dispatch_if_admitted(
                SimdDispatchContext::capture(),
                b"QZ",
                [(0x80, 0x80)].into_iter(),
                wide_unbordered_suffix,
                0,
                usize::MAX,
                BuildLimits::unlimited(),
            )
            .unwrap();
        assert!(without_ascii_scanner.is_none());
        let strict_without_ascii_scanner =
            BoundedLiteralClassRunPlan::build_with_dispatch_if_admitted(
                SimdDispatchContext::capture(),
                b"abaaaabb",
                [(0x80, 0x80)].into_iter(),
                b"abababab",
                0,
                0,
                BuildLimits::unlimited(),
            )
            .unwrap()
            .expect("strict repetition improvement does not require SIMD");
        assert_eq!(strict_without_ascii_scanner.preferred_anchor, Anchor::Prefix);

        let exact_prefix = b"abaaaabb";
        let exact_suffix = b"abababab";
        let admitted = ascii(
            exact_prefix,
            exact_suffix,
            0,
            BuildLimits::unlimited(),
        )
        .unwrap()
        .expect("strict repetition improvement provides an architecture-neutral receipt");
        let baseline = admitted.build_accounting();
        let exact = BuildLimits {
            max_literal_bytes: baseline.literal_bytes,
            max_class_ranges: baseline.class_ranges,
            max_class_members: baseline.class_members,
            max_build_work: baseline.work_upper_bound,
            max_scratch_bytes: baseline.scratch_bytes,
            max_persistent_bytes: baseline.persistent_bytes,
            max_peak_bytes: baseline.peak_bytes,
        };
        assert!(ascii(exact_prefix, exact_suffix, 0, exact)
            .unwrap()
            .is_some());
        let below = BuildLimits {
            max_build_work: baseline.work_upper_bound - 1,
            ..exact
        };
        assert!(matches!(
            ascii(exact_prefix, exact_suffix, 0, below),
            Err(BuildError::WorkLimit { needed, limit })
                if needed == baseline.work_upper_bound
                    && limit == baseline.work_upper_bound - 1
        ));
        let declined_resource_limit = BuildLimits {
            max_literal_bytes: 0,
            ..BuildLimits::unlimited()
        };
        assert!(matches!(
            ascii(b"QZ", wide_unbordered_suffix, 0, declined_resource_limit),
            Err(BuildError::LiteralBytesLimit { .. })
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one matrix keeps complement barriers, UTF-8 validity, windows, and both repetition minima adjacent"
    )]
    fn dispatched_unicode_complement_scanner_matches_upstream_for_every_byte_barrier() {
        let dispatch = SimdDispatchContext::capture();
        let mut haystacks = vec![
            b"".to_vec(),
            b"az".to_vec(),
            b"--abz--".to_vec(),
            "--aé文🦀z--".as_bytes().to_vec(),
            b"--a\xC0\xAFz--aokz--".to_vec(),
            b"--a\xED\xA0\x80z--aokz--".to_vec(),
            b"--a\xF4\x90\x80\x80z--aokz--".to_vec(),
            b"--a\xF0\x9F\x92z--aokz--".to_vec(),
        ];
        for barrier in [b'\n', b'\r', b'z'].into_iter().chain(0x80_u8..=u8::MAX) {
            let mut haystack = b"--aqq".to_vec();
            haystack.push(barrier);
            haystack.extend_from_slice(b"qqz--aokz--");
            haystacks.push(haystack);
        }

        for (minimum, pattern) in [
            (SearchRunMinimum::Zero, r"a[^z\r\n]*z"),
            (SearchRunMinimum::One, r"a[^z\r\n]+z"),
        ] {
            let plan = LiteralClassRunSearchPlan::build_unicode_all_non_ascii_with_dispatch(
                dispatch,
                b"a",
                [
                    ('\0', '\u{9}'),
                    ('\u{B}', '\u{C}'),
                    ('\u{E}', 'y'),
                    ('{', char::MAX),
                ]
                .into_iter(),
                b"z",
                minimum,
                BuildLimits::unlimited(),
            )
            .unwrap();
            let oracle = RegexBuilder::new(pattern).build().unwrap();

            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = Window::new(start, end);
                        let expected = oracle
                            .find(&haystack[start..end])
                            .map(|matched| (start + matched.start(), start + matched.end()));
                        let expected_shortest = oracle
                            .shortest_match(&haystack[start..end])
                            .map(|matched_end| start + matched_end);
                        assert_eq!(
                            plan.find_window(haystack, window, SearchLimits::unlimited())
                                .unwrap()
                                .0,
                            expected,
                            "pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                        );
                        assert_eq!(
                            plan.shortest_window(haystack, window, SearchLimits::unlimited())
                                .unwrap()
                                .0,
                            expected_shortest,
                            "shortest pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                        );
                        assert_eq!(
                            plan.is_match_window_value(
                                haystack,
                                window,
                                SearchLimits::unlimited(),
                            )
                            .unwrap(),
                            expected.is_some(),
                            "exists pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                        );
                    }
                }
            }

            let mut long = b"--a".to_vec();
            long.extend(core::iter::repeat_n(b'q', 8_193));
            long.extend_from_slice("é文🦀".as_bytes());
            long.extend(core::iter::repeat_n(b'x', 8_191));
            long.extend_from_slice(b"z--");
            let expected = oracle
                .find(&long)
                .map(|matched| (matched.start(), matched.end()));
            let (actual, accounting) = plan.find(&long, SearchLimits::unlimited()).unwrap();
            assert_eq!(actual, expected);
            let upper = plan.search_upper_bounds(long.len()).unwrap();
            assert!(accounting.classifications <= upper.classifications);
            assert!(accounting.source_reads <= accounting.source_reads_upper_bound);
            assert!(u64::try_from(accounting.work).unwrap() <= accounting.work_upper_bound);
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one boundary matrix keeps the initial scalar proof, sustained scanner handoff, Unicode decoding, and window edges adjacent"
    )]
    fn dispatched_unicode_value_initial_proof_covers_scanner_handoff_boundaries() {
        let dispatch = SimdDispatchContext::capture();
        for (minimum, pattern) in [
            (SearchRunMinimum::Zero, r"a[^z\r\n]*z"),
            (SearchRunMinimum::One, r"a[^z\r\n]+z"),
        ] {
            let plan = LiteralClassRunSearchPlan::build_unicode_all_non_ascii_with_dispatch(
                dispatch,
                b"a",
                [
                    ('\0', '\u{9}'),
                    ('\u{B}', '\u{C}'),
                    ('\u{E}', 'y'),
                    ('{', char::MAX),
                ]
                .into_iter(),
                b"z",
                minimum,
                BuildLimits::unlimited(),
            )
            .unwrap();
            if !matches!(plan.ascii_scanner.as_ref(), Some(AsciiClassScanner::Run(_))) {
                return;
            }
            let oracle = RegexBuilder::new(pattern).build().unwrap();

            for corridor_len in [14, 15, 16, 17, 31, 32, 33, 4_093] {
                let mut ascii_success = b"--a".to_vec();
                ascii_success.extend(core::iter::repeat_n(b'q', corridor_len));
                ascii_success.extend_from_slice(b"z--");

                let first_half = corridor_len / 2;
                let mut unicode_success = b"--a".to_vec();
                unicode_success.extend(core::iter::repeat_n(b'q', first_half));
                unicode_success.extend_from_slice("é".as_bytes());
                unicode_success.extend(core::iter::repeat_n(b'q', corridor_len - first_half));
                unicode_success.extend_from_slice(b"z--");

                let mut excluded_barrier = b"--a".to_vec();
                excluded_barrier.extend(core::iter::repeat_n(b'q', corridor_len));
                excluded_barrier.extend_from_slice(b"\nz--");

                let mut invalid_then_later = b"--a".to_vec();
                invalid_then_later.extend(core::iter::repeat_n(b'q', corridor_len));
                invalid_then_later.extend_from_slice(b"\xF0\x9F\x92z--aokz--");

                let mut unterminated = b"--a".to_vec();
                unterminated.extend(core::iter::repeat_n(b'q', corridor_len));

                for haystack in [
                    &ascii_success,
                    &unicode_success,
                    &excluded_barrier,
                    &invalid_then_later,
                    &unterminated,
                ] {
                    let suffix_edge = haystack.len().saturating_sub(3);
                    for window in [
                        Window::full(haystack),
                        Window::new(2, haystack.len()),
                        Window::new(3, haystack.len()),
                        Window::new(2, suffix_edge),
                    ] {
                        let expected = oracle.is_match(&haystack[window.start()..window.end()]);
                        assert_eq!(
                            plan.is_match_window_value(
                                haystack,
                                window,
                                SearchLimits::unlimited(),
                            )
                            .unwrap(),
                            expected,
                            "pattern={pattern:?} corridor_len={corridor_len} haystack={haystack:?} window={}..{}",
                            window.start(),
                            window.end()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn ordinary_dense_byte_plan_does_not_opt_into_unicode_complement_dispatch() {
        let plan = LiteralClassRunLiteralPlan::build_with_dispatch(
            SimdDispatchContext::capture(),
            b"A",
            [(0, b'A' - 1), (b'A' + 1, b'Z' - 1), (b'Z' + 1, 0x7f)].into_iter(),
            b"Z",
            BuildLimits::unlimited(),
        )
        .unwrap();
        if let Some(AsciiClassScanner::Run(scanner)) = plan.ascii_scanner {
            assert!(!scanner.selection().variant_id.contains("complement"));
            assert!(!scanner.selection().variant_id.contains("match16"));
        }
        for haystack in [b"AZ".as_slice(), b"AabcZ", b"A\x80Z--AokZ"] {
            let scalar = LiteralClassRunLiteralPlan::build(
                b"A",
                [(0, b'A' - 1), (b'A' + 1, b'Z' - 1), (b'Z' + 1, 0x7f)].into_iter(),
                b"Z",
                BuildLimits::unlimited(),
            )
            .unwrap();
            assert_eq!(
                plan.count(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count,
                scalar
                    .count(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count
            );
        }
    }

    #[test]
    fn unicode_all_non_ascii_builder_reproves_coverage_and_literals() {
        assert!(matches!(
            LiteralClassRunSearchPlan::build_unicode_all_non_ascii(
                b"a",
                [('\0', '\u{7F}'), ('\u{81}', char::MAX)].into_iter(),
                b"z",
                SearchRunMinimum::Zero,
                BuildLimits::unlimited(),
            ),
            Err(BuildError::UnsupportedUnicodeClass)
        ));
        assert!(matches!(
            LiteralClassRunSearchPlan::build_unicode_all_non_ascii(
                "é".as_bytes(),
                [('\0', 'y'), ('{', char::MAX)].into_iter(),
                b"z",
                SearchRunMinimum::Zero,
                BuildLimits::unlimited(),
            ),
            Err(BuildError::NonAsciiUnicodeLiteral)
        ));
        assert!(matches!(
            LiteralClassRunSearchPlan::build_unicode_all_non_ascii(
                b"a",
                [('a', char::MAX), ('b', 'c')].into_iter(),
                b"z",
                SearchRunMinimum::Zero,
                BuildLimits::unlimited(),
            ),
            Err(BuildError::NonCanonicalClass)
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table-driven test closes exact replay and every nonzero Unicode build dimension"
    )]
    fn unicode_all_non_ascii_build_accounting_replays_exact_source_ranges() {
        let ranges = [('a', 'a'), ('\u{80}', char::MAX)];
        let baseline = LiteralClassRunSearchPlan::build_unicode_all_non_ascii(
            b"q",
            ranges.into_iter(),
            b"z",
            SearchRunMinimum::Zero,
            BuildLimits::unlimited(),
        )
        .unwrap()
        .build_accounting();
        assert_eq!(baseline.class_ranges, 2);
        assert_eq!(baseline.class_members, 1);
        let exact = BuildLimits {
            max_literal_bytes: baseline.literal_bytes,
            max_class_ranges: baseline.class_ranges,
            max_class_members: baseline.class_members,
            max_build_work: baseline.work_upper_bound,
            max_scratch_bytes: baseline.scratch_bytes,
            max_persistent_bytes: baseline.persistent_bytes,
            max_peak_bytes: baseline.peak_bytes,
        };
        assert_eq!(
            LiteralClassRunSearchPlan::build_unicode_all_non_ascii(
                b"q",
                ranges.into_iter(),
                b"z",
                SearchRunMinimum::Zero,
                exact,
            )
            .unwrap()
            .build_accounting(),
            baseline
        );

        let mut below = exact;
        below.max_literal_bytes -= 1;
        assert!(matches!(
            LiteralClassRunSearchPlan::build_unicode_all_non_ascii(
                b"q",
                ranges.into_iter(),
                b"z",
                SearchRunMinimum::Zero,
                below,
            ),
            Err(BuildError::LiteralBytesLimit { .. })
        ));
        below = exact;
        below.max_class_ranges -= 1;
        assert!(matches!(
            LiteralClassRunSearchPlan::build_unicode_all_non_ascii(
                b"q",
                ranges.into_iter(),
                b"z",
                SearchRunMinimum::Zero,
                below,
            ),
            Err(BuildError::ClassRangesLimit {
                needed: 2,
                limit: 1
            })
        ));
        below = exact;
        below.max_class_members -= 1;
        assert!(matches!(
            LiteralClassRunSearchPlan::build_unicode_all_non_ascii(
                b"q",
                ranges.into_iter(),
                b"z",
                SearchRunMinimum::Zero,
                below,
            ),
            Err(BuildError::ClassMembersLimit {
                needed: 1,
                limit: 0
            })
        ));
        below = exact;
        below.max_build_work -= 1;
        assert!(matches!(
            LiteralClassRunSearchPlan::build_unicode_all_non_ascii(
                b"q",
                ranges.into_iter(),
                b"z",
                SearchRunMinimum::Zero,
                below,
            ),
            Err(BuildError::WorkLimit { needed, limit })
                if needed == baseline.work_upper_bound && limit + 1 == needed
        ));
        below = exact;
        below.max_persistent_bytes -= 1;
        assert!(matches!(
            LiteralClassRunSearchPlan::build_unicode_all_non_ascii(
                b"q",
                ranges.into_iter(),
                b"z",
                SearchRunMinimum::Zero,
                below,
            ),
            Err(BuildError::PersistentLimit { .. })
        ));
        below = exact;
        below.max_peak_bytes -= 1;
        assert!(matches!(
            LiteralClassRunSearchPlan::build_unicode_all_non_ascii(
                b"q",
                ranges.into_iter(),
                b"z",
                SearchRunMinimum::Zero,
                below,
            ),
            Err(BuildError::PeakLimit { .. })
        ));
    }

    #[test]
    fn unicode_all_non_ascii_supports_an_empty_materialized_ascii_class() {
        let plan = LiteralClassRunSearchPlan::build_unicode_all_non_ascii(
            b"a",
            [('\u{80}', char::MAX)].into_iter(),
            b"z",
            SearchRunMinimum::Zero,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let dispatched = LiteralClassRunSearchPlan::build_unicode_all_non_ascii_with_dispatch(
            SimdDispatchContext::capture(),
            b"a",
            [('\u{80}', char::MAX)].into_iter(),
            b"z",
            SearchRunMinimum::Zero,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(plan.build_accounting().class_ranges, 1);
        assert_eq!(plan.build_accounting().class_members, 0);
        if let Some(AsciiClassScanner::Run(scanner)) = dispatched.ascii_scanner {
            assert!(!scanner.selection().variant_id.contains("complement"));
            assert!(!scanner.selection().variant_id.contains("match16"));
        }
        for (haystack, expected) in [
            (b"az".as_slice(), Some((0, 2))),
            ("aé文🦀z".as_bytes(), Some((0, "aé文🦀z".len()))),
            (b"abz".as_slice(), None),
            (b"a\x80z--az".as_slice(), Some((5, 7))),
        ] {
            assert_eq!(
                plan.find(haystack, SearchLimits::unlimited()).unwrap().0,
                expected,
                "haystack={haystack:?}"
            );
            assert_eq!(
                dispatched
                    .find(haystack, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                expected,
                "dispatched haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn finite_unicode_decode_stops_at_the_exact_work_boundary() {
        let plan = unicode_generalized_plan();
        let haystack = "a🦀z".as_bytes();
        assert!(matches!(
            plan.find(
                haystack,
                SearchLimits {
                    max_work_upper_bound: 27,
                    max_candidate_visits: usize::MAX,
                    max_scratch_bytes: 0,
                },
            ),
            Err(SearchError::WorkLimit {
                needed: 29,
                limit: 27
            })
        ));

        let (_, ordinary) = plan.find(haystack, SearchLimits::unlimited()).unwrap();
        let (_, metered) = plan
            .find(
                haystack,
                SearchLimits {
                    max_work_upper_bound: ordinary.work_upper_bound - 1,
                    max_candidate_visits: usize::MAX,
                    max_scratch_bytes: 0,
                },
            )
            .unwrap();
        let exact_work = u64::try_from(metered.work).unwrap();
        assert_eq!(
            plan.find(
                haystack,
                SearchLimits {
                    max_work_upper_bound: exact_work,
                    max_candidate_visits: usize::MAX,
                    max_scratch_bytes: 0,
                },
            )
            .unwrap()
            .0,
            Some((0, haystack.len()))
        );
        assert!(matches!(
            plan.find(
                haystack,
                SearchLimits {
                    max_work_upper_bound: exact_work - 1,
                    max_candidate_visits: usize::MAX,
                    max_scratch_bytes: 0,
                },
            ),
            Err(SearchError::WorkLimit { needed, limit })
                if needed == exact_work && limit + 1 == needed
        ));
        assert!(
            plan.is_match_window_value(
                haystack,
                Window::full(haystack),
                SearchLimits {
                    max_work_upper_bound: exact_work,
                    max_candidate_visits: usize::MAX,
                    max_scratch_bytes: 0,
                },
            )
            .unwrap()
        );
        assert!(matches!(
            plan.is_match_window_value(
                haystack,
                Window::full(haystack),
                SearchLimits {
                    max_work_upper_bound: exact_work - 1,
                    max_candidate_visits: usize::MAX,
                    max_scratch_bytes: 0,
                },
            ),
            Err(SearchError::WorkLimit { needed, limit })
                if needed == exact_work && limit + 1 == needed
        ));

        let mut mixed = b"a".to_vec();
        mixed.extend_from_slice("é€🦀".as_bytes());
        mixed.extend(core::iter::repeat_n(b'q', 97));
        mixed.push(b'z');
        let (_, ordinary) = plan.find(&mixed, SearchLimits::unlimited()).unwrap();
        let (expected, metered) = plan
            .find(
                &mixed,
                SearchLimits {
                    max_work_upper_bound: ordinary.work_upper_bound - 1,
                    max_candidate_visits: usize::MAX,
                    max_scratch_bytes: 0,
                },
            )
            .unwrap();
        let exact_work = u64::try_from(metered.work).unwrap();
        assert_eq!(expected, Some((0, mixed.len())));
        assert_eq!(
            plan.find(
                &mixed,
                SearchLimits {
                    max_work_upper_bound: exact_work,
                    max_candidate_visits: usize::MAX,
                    max_scratch_bytes: 0,
                },
            )
            .unwrap()
            .0,
            expected
        );
        assert!(matches!(
            plan.find(
                &mixed,
                SearchLimits {
                    max_work_upper_bound: exact_work - 1,
                    max_candidate_visits: usize::MAX,
                    max_scratch_bytes: 0,
                },
            ),
            Err(SearchError::WorkLimit { needed, limit })
                if needed == exact_work && limit + 1 == needed
        ));
    }

    #[test]
    fn suffix_anchor_prefix_class_overlap_and_underflow_match_reference() {
        let plan = LiteralClassRunLiteralPlan::build(
            b"ya",
            [(b'x', b'y')].into_iter(),
            b"bbbb",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let haystack = b"xybbbb--yaxybbbb";
        let oracle = RegexBuilder::new(r"ya[xy]+bbbb")
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(
            plan.find(haystack, SearchLimits::unlimited()).unwrap().0,
            oracle
                .find(haystack)
                .map(|matched| (matched.start(), matched.end()))
        );
        assert_eq!(
            plan.shortest(haystack, SearchLimits::unlimited())
                .unwrap()
                .0,
            oracle.shortest_match(haystack)
        );
        assert_eq!(
            plan.find(haystack, SearchLimits::unlimited()).unwrap().0,
            Some((8, 16))
        );
    }

    #[test]
    fn search_work_and_candidate_limits_meter_distinct_actual_units() {
        let plan = generalized_plan(
            b"a",
            [(b'a', b'b')].into_iter(),
            b"c",
            SearchRunMinimum::One,
        );
        let haystack = b"aaabc";
        let (_, accounting) = plan.find(haystack, SearchLimits::unlimited()).unwrap();
        let exact_work = u64::try_from(accounting.work).unwrap();
        assert!(
            plan.find(
                haystack,
                SearchLimits {
                    max_work_upper_bound: exact_work,
                    max_candidate_visits: usize::MAX,
                    max_scratch_bytes: 0,
                },
            )
            .is_ok()
        );
        assert!(matches!(
            plan.find(
                haystack,
                SearchLimits {
                    max_work_upper_bound: exact_work - 1,
                    max_candidate_visits: usize::MAX,
                    max_scratch_bytes: 0,
                },
            ),
            Err(SearchError::WorkLimit { needed, limit })
                if needed == exact_work && limit == exact_work - 1
        ));
        assert!(matches!(
            plan.find(
                haystack,
                SearchLimits {
                    max_work_upper_bound: u64::MAX,
                    max_candidate_visits: 0,
                    max_scratch_bytes: 0,
                },
            ),
            Err(SearchError::CandidateLimit {
                needed: 1,
                limit: 0
            })
        ));
        assert!(matches!(
            plan.is_match_window_value(
                haystack,
                Window::full(haystack),
                SearchLimits {
                    max_work_upper_bound: u64::MAX,
                    max_candidate_visits: 0,
                    max_scratch_bytes: 0,
                },
            ),
            Err(SearchError::CandidateLimit {
                needed: 1,
                limit: 0
            })
        ));
        assert_eq!(
            plan.find(
                b"xxxxx",
                SearchLimits {
                    max_work_upper_bound: u64::MAX,
                    max_candidate_visits: 0,
                    max_scratch_bytes: 0,
                },
            )
            .unwrap()
            .0,
            None
        );
        assert!(
            !plan
                .is_match_window_value(
                    b"xxxxx",
                    Window::full(b"xxxxx"),
                    SearchLimits {
                        max_work_upper_bound: u64::MAX,
                        max_candidate_visits: 0,
                        max_scratch_bytes: 0,
                    },
                )
                .unwrap()
        );
    }

    #[test]
    fn generalized_builder_revalidates_search_only_guards_and_exact_limits() {
        assert!(matches!(
            LiteralClassRunSearchPlan::build(
                b"",
                [(b'a', b'z')].into_iter(),
                b"T",
                SearchRunMinimum::Zero,
                BoundarySemantics::CompleteAsciiWordRun,
                BuildLimits::unlimited(),
            ),
            Err(BuildError::UnsupportedSearchMinimum)
        ));
        assert!(matches!(
            LiteralClassRunSearchPlan::build(
                b"",
                [(b'!', b'z')].into_iter(),
                b"T",
                SearchRunMinimum::One,
                BoundarySemantics::CompleteAsciiWordRun,
                BuildLimits::unlimited(),
            ),
            Err(BuildError::ClassOutsideAsciiWord)
        ));
        assert!(matches!(
            LiteralClassRunSearchPlan::build(
                b"",
                [(b'A', b'Z')].into_iter(),
                b"T-",
                SearchRunMinimum::One,
                BoundarySemantics::CompleteAsciiWordRun,
                BuildLimits::unlimited(),
            ),
            Err(BuildError::SuffixByteOutsideAsciiWord)
        ));
        assert!(matches!(
            LiteralClassRunSearchPlan::build(
                b"a",
                [(b'a', b'b')].into_iter(),
                b"b",
                SearchRunMinimum::One,
                BoundarySemantics::Unguarded,
                BuildLimits::unlimited(),
            ),
            Err(BuildError::SuffixBoundaryInClass)
        ));

        let baseline = generalized_plan(
            b"a",
            [(b'a', b'b')].into_iter(),
            b"c",
            SearchRunMinimum::One,
        )
        .build_accounting();
        let exact = BuildLimits {
            max_literal_bytes: baseline.literal_bytes,
            max_class_ranges: baseline.class_ranges,
            max_class_members: baseline.class_members,
            max_build_work: baseline.work_upper_bound,
            max_scratch_bytes: baseline.scratch_bytes,
            max_persistent_bytes: baseline.persistent_bytes,
            max_peak_bytes: baseline.peak_bytes,
        };
        assert_eq!(
            LiteralClassRunSearchPlan::build(
                b"a",
                [(b'a', b'b')].into_iter(),
                b"c",
                SearchRunMinimum::One,
                BoundarySemantics::Unguarded,
                exact,
            )
            .unwrap()
            .build_accounting(),
            baseline
        );
        let mut below = exact;
        below.max_build_work -= 1;
        assert!(matches!(
            LiteralClassRunSearchPlan::build(
                b"a",
                [(b'a', b'b')].into_iter(),
                b"c",
                SearchRunMinimum::One,
                BoundarySemantics::Unguarded,
                below,
            ),
            Err(BuildError::WorkLimit { .. })
        ));
    }

    #[test]
    fn generalized_shortest_value_preserves_fallback_resources_and_errors() {
        let plan = generalized_plan(
            b"a",
            [(b'a', b'b')].into_iter(),
            b"c",
            SearchRunMinimum::One,
        );
        let haystack = b"!!aabbc!!";
        let window = Window::full(haystack);
        let (expected, accounting) = plan
            .shortest_window(haystack, window, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            plan.shortest_window_value(haystack, window, SearchLimits::unlimited())
                .unwrap(),
            expected
        );
        assert!(accounting.work > 0);
        assert!(accounting.candidate_visits > 0);

        let exact = SearchLimits {
            max_work_upper_bound: u64::try_from(accounting.work).unwrap(),
            max_candidate_visits: accounting.candidate_visits,
            max_scratch_bytes: 0,
        };
        assert_eq!(
            plan.shortest_window_value(haystack, window, exact)
                .unwrap(),
            plan.shortest_window(haystack, window, exact).unwrap().0
        );

        let work_below = SearchLimits {
            max_work_upper_bound: u64::try_from(accounting.work - 1).unwrap(),
            max_candidate_visits: usize::MAX,
            max_scratch_bytes: 0,
        };
        assert_eq!(
            plan.shortest_window_value(haystack, window, work_below)
                .unwrap_err(),
            plan.shortest_window(haystack, window, work_below)
                .unwrap_err()
        );

        let candidates_below = SearchLimits {
            max_work_upper_bound: u64::MAX,
            max_candidate_visits: accounting.candidate_visits - 1,
            max_scratch_bytes: 0,
        };
        assert_eq!(
            plan.shortest_window_value(haystack, window, candidates_below)
                .unwrap_err(),
            plan.shortest_window(haystack, window, candidates_below)
                .unwrap_err()
        );

        let custom = SearchLimits {
            max_work_upper_bound: u64::MAX,
            max_candidate_visits: usize::MAX,
            max_scratch_bytes: 0,
        };
        assert_eq!(
            plan.shortest_window_value(haystack, window, custom)
                .unwrap(),
            plan.shortest_window(haystack, window, custom).unwrap().0
        );

        for invalid in [
            Window::new(haystack.len(), haystack.len() - 1),
            Window::new(0, haystack.len() + 1),
        ] {
            assert_eq!(
                plan.shortest_window_value(haystack, invalid, SearchLimits::unlimited())
                    .unwrap_err(),
                plan.shortest_window(haystack, invalid, SearchLimits::unlimited())
                    .unwrap_err()
            );
        }

        let prefix_only = generalized_plan(
            b"a",
            [(b'b', b'c')].into_iter(),
            b"",
            SearchRunMinimum::Zero,
        );
        let prefix_haystack = b"!abcb!";
        assert_eq!(
            prefix_only
                .shortest_window_value(
                    prefix_haystack,
                    Window::full(prefix_haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
            Some(2)
        );

        let guarded = LiteralClassRunSearchPlan::build(
            b"",
            [(b'A', b'Z'), (b'a', b'z')].into_iter(),
            b"TRAILER",
            SearchRunMinimum::One,
            BoundarySemantics::CompleteAsciiWordRun,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let guarded_haystack = b"!abcTRAILER!";
        assert_eq!(
            guarded
                .shortest_window_value(
                    guarded_haystack,
                    Window::full(guarded_haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
            guarded
                .shortest_window(
                    guarded_haystack,
                    Window::full(guarded_haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap()
                .0
        );
    }

    #[test]
    fn bounded_two_barrier_selected_shortest_and_value_search_match_every_window() {
        let plan = bounded_plan();
        let oracle = RegexBuilder::new(r"ab[01]{0,2}xy")
            .unicode(false)
            .build()
            .unwrap();
        for haystack in [
            b"".as_slice(),
            b"abxy",
            b"ab0xy",
            b"ab01xy",
            b"ab001xy--ab1xy",
            b"zab01xy",
            b"abab01xy",
            b"ab2xy--ab0xy",
            b"ab01xz--abxy",
            b"ab01xyabxy",
            b"xxab00xyyy",
        ] {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = Window::new(start, end);
                    let expected = oracle
                        .find(&haystack[start..end])
                        .map(|matched| (start + matched.start(), start + matched.end()));
                    let expected_shortest = oracle
                        .shortest_match(&haystack[start..end])
                        .map(|matched_end| start + matched_end);
                    assert_eq!(
                        plan.find_window(haystack, window, SearchLimits::unlimited())
                            .unwrap()
                            .0,
                        expected,
                        "selected haystack={haystack:?} window={start}..{end}"
                    );
                    assert_eq!(
                        plan.find_window_value(haystack, window, SearchLimits::unlimited())
                            .unwrap(),
                        expected,
                        "value span haystack={haystack:?} window={start}..{end}"
                    );
                    assert_eq!(
                        plan.shortest_window(haystack, window, SearchLimits::unlimited())
                            .unwrap()
                            .0,
                        expected_shortest,
                        "shortest haystack={haystack:?} window={start}..{end}"
                    );
                    assert_eq!(
                        plan.shortest_window_value(
                            haystack,
                            window,
                            SearchLimits::unlimited(),
                        )
                        .unwrap(),
                        expected_shortest,
                        "value shortest haystack={haystack:?} window={start}..{end}"
                    );
                    assert_eq!(
                        plan.is_match_window_value(haystack, window, SearchLimits::unlimited())
                            .unwrap(),
                        expected.is_some(),
                        "exists haystack={haystack:?} window={start}..{end}"
                    );
                }
            }
        }
    }

    #[test]
    fn bounded_two_barrier_builder_and_search_limits_are_exactly_enforced() {
        assert!(matches!(
            BoundedLiteralClassRunPlan::build(
                b"ab",
                [(b'0', b'1')].into_iter(),
                b"xy",
                3,
                2,
                BuildLimits::unlimited(),
            ),
            Err(BuildError::InvalidFiniteBounds {
                minimum: 3,
                maximum: 2
            })
        ));
        assert!(matches!(
            BoundedLiteralClassRunPlan::build(
                b"a0",
                [(b'0', b'1')].into_iter(),
                b"xy",
                0,
                2,
                BuildLimits::unlimited(),
            ),
            Err(BuildError::PrefixBoundaryInClass)
        ));
        assert!(matches!(
            BoundedLiteralClassRunPlan::build(
                b"ab",
                [(b'0', b'1')].into_iter(),
                b"1y",
                0,
                2,
                BuildLimits::unlimited(),
            ),
            Err(BuildError::SuffixBoundaryInClass)
        ));

        let baseline = bounded_plan().build_accounting();
        let exact = BuildLimits {
            max_literal_bytes: baseline.literal_bytes,
            max_class_ranges: baseline.class_ranges,
            max_class_members: baseline.class_members,
            max_build_work: baseline.work_upper_bound,
            max_scratch_bytes: baseline.scratch_bytes,
            max_persistent_bytes: baseline.persistent_bytes,
            max_peak_bytes: baseline.peak_bytes,
        };
        assert_eq!(
            BoundedLiteralClassRunPlan::build(
                b"ab",
                [(b'0', b'1')].into_iter(),
                b"xy",
                0,
                2,
                exact,
            )
            .unwrap()
            .build_accounting(),
            baseline
        );
        let mut below = exact;
        below.max_build_work -= 1;
        assert!(matches!(
            BoundedLiteralClassRunPlan::build(
                b"ab",
                [(b'0', b'1')].into_iter(),
                b"xy",
                0,
                2,
                below,
            ),
            Err(BuildError::WorkLimit { .. })
        ));
        below = exact;
        below.max_persistent_bytes -= 1;
        assert!(matches!(
            BoundedLiteralClassRunPlan::build(
                b"ab",
                [(b'0', b'1')].into_iter(),
                b"xy",
                0,
                2,
                below,
            ),
            Err(BuildError::PersistentLimit { .. })
        ));

        let plan = bounded_plan();
        let haystack = b"!!ab01xy";
        let (_, accounting) = plan.find(haystack, SearchLimits::unlimited()).unwrap();
        let exact_work = u64::try_from(accounting.work).unwrap();
        assert!(
            plan.find(
                haystack,
                SearchLimits {
                    max_work_upper_bound: exact_work,
                    max_candidate_visits: accounting.candidate_visits,
                    max_scratch_bytes: 0,
                },
            )
            .is_ok()
        );
        assert!(matches!(
            plan.find(
                haystack,
                SearchLimits {
                    max_work_upper_bound: exact_work - 1,
                    max_candidate_visits: usize::MAX,
                    max_scratch_bytes: 0,
                },
            ),
            Err(SearchError::WorkLimit { needed, limit })
                if needed == exact_work && limit == exact_work - 1
        ));
        assert!(matches!(
            plan.find(
                haystack,
                SearchLimits {
                    max_work_upper_bound: u64::MAX,
                    max_candidate_visits: 0,
                    max_scratch_bytes: 0,
                },
            ),
            Err(SearchError::CandidateLimit {
                needed: 1,
                limit: 0
            })
        ));
    }

    #[test]
    fn bounded_two_barrier_search_retains_no_cross_plan_or_source_state() {
        let first = bounded_plan();
        let second = BoundedLiteralClassRunPlan::build(
            b"cd",
            [(b'2', b'3')].into_iter(),
            b"uv",
            1,
            2,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let mut same_allocation = b"--ab01xy--".to_vec();
        assert_eq!(
            first
                .find(&same_allocation, SearchLimits::unlimited())
                .unwrap()
                .0,
            Some((2, 8))
        );
        same_allocation.copy_from_slice(b"--cd23uv--");
        assert_eq!(
            second
                .find(&same_allocation, SearchLimits::unlimited())
                .unwrap()
                .0,
            Some((2, 8))
        );
        assert_eq!(
            first
                .find(&same_allocation, SearchLimits::unlimited())
                .unwrap()
                .0,
            None
        );
        same_allocation.copy_from_slice(b"--ab00xy--");
        assert_eq!(
            first
                .find_window_value(
                    &same_allocation,
                    Window::full(&same_allocation),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
            Some((2, 8))
        );
    }

    #[test]
    fn bounded_two_barrier_scans_only_maximum_plus_one_class_bytes() {
        let plan = bounded_plan();
        let mut haystack = b"ab".to_vec();
        haystack.extend(core::iter::repeat_n(b'0', 4_096));
        haystack.extend_from_slice(b"xy--");
        let later_start = haystack.len();
        haystack.extend_from_slice(b"ab1xy");
        let expected = Some((later_start, later_start + 5));

        let (selected, selected_accounting) =
            plan.find(&haystack, SearchLimits::unlimited()).unwrap();
        let (shortest, shortest_accounting) = plan
            .shortest_window(
                &haystack,
                Window::full(&haystack),
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(selected, expected);
        assert_eq!(shortest, expected.map(|(_, end)| end));
        assert_eq!(selected_accounting.classifications, 5);
        assert_eq!(shortest_accounting.classifications, 5);
        assert!(selected_accounting.source_reads <= selected_accounting.source_reads_upper_bound);
        assert!(shortest_accounting.source_reads <= shortest_accounting.source_reads_upper_bound);
        assert_eq!(
            plan.find_window_value(
                &haystack,
                Window::full(&haystack),
                SearchLimits::unlimited(),
            )
            .unwrap(),
            expected
        );
        assert_eq!(
            plan.shortest_window_value(
                &haystack,
                Window::full(&haystack),
                SearchLimits::unlimited(),
            )
            .unwrap(),
            expected.map(|(_, end)| end)
        );

        let unbounded_maximum = BoundedLiteralClassRunPlan::build(
            b"ab",
            [(b'0', b'1')].into_iter(),
            b"xy",
            0,
            usize::MAX,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(
            unbounded_maximum
                .find(b"ab000xy", SearchLimits::unlimited())
                .unwrap()
                .0,
            Some((0, 7))
        );
    }

    #[test]
    fn bounded_zero_maximum_still_classifies_an_available_boundary() {
        let plan = BoundedLiteralClassRunPlan::build(
            b"ab",
            [(b'0', b'1')].into_iter(),
            b"xy",
            0,
            0,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let (selected, selected_accounting) =
            plan.find(b"abxy", SearchLimits::unlimited()).unwrap();
        let (shortest, shortest_accounting) = plan
            .shortest_window(
                b"abxy",
                Window::full(b"abxy"),
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(selected, Some((0, 4)));
        assert_eq!(shortest, Some(4));
        assert_eq!(selected_accounting.classifications, 1);
        assert_eq!(shortest_accounting.classifications, 1);
        assert_eq!(
            plan.find(b"ab0xy", SearchLimits::unlimited()).unwrap().0,
            None
        );
    }

    #[test]
    fn bounded_dispatched_terminal_recovery_fits_the_max_plus_one_upper_bound() {
        let plan = BoundedLiteralClassRunPlan::build_with_dispatch(
            SimdDispatchContext::capture(),
            b"ab",
            [(b'0', b'9')].into_iter(),
            b"xy",
            0,
            15,
            BuildLimits::unlimited(),
        )
        .unwrap();
        // Keep a complete max+1 scan slice after the prefix while placing the
        // first nonmember inside it. SIMD run leaves may classify that failed
        // block once as a vector and again while recovering the exact edge.
        let haystack = b"ab000xy----------------";
        let (matched, accounting) = plan
            .find(haystack, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, Some((0, 7)));
        assert!(accounting.source_reads <= accounting.source_reads_upper_bound);
        assert!(u64::try_from(accounting.work).unwrap() <= accounting.work_upper_bound);
    }

    #[test]
    fn bounded_preferred_anchor_and_value_routes_share_limits() {
        let cases = [
            (
                BoundedLiteralClassRunPlan::build(
                    b"QZ",
                    [(b'0', b'9')].into_iter(),
                    b"aa",
                    0,
                    2,
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                Anchor::Prefix,
                b"aaaaaaaaaaaaaaaa--QZ12aa".as_slice(),
            ),
            (
                BoundedLiteralClassRunPlan::build(
                    b"aa",
                    [(b'0', b'9')].into_iter(),
                    b"QZ",
                    0,
                    2,
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                Anchor::Suffix,
                b"aaaaaaaaaaaaaaaa--aa12QZ".as_slice(),
            ),
        ];
        for (plan, expected_anchor, haystack) in cases {
            assert_eq!(plan.preferred_anchor, expected_anchor);
            let (matched, accounting) = plan
                .is_match_window(
                    haystack,
                    Window::full(haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap();
            assert!(matched);
            assert_eq!(
                accounting.operation_id,
                BOUNDED_EXISTS_SEARCH_OPERATION_ID
            );
            let exact_work = u64::try_from(accounting.work).unwrap();
            let exact = SearchLimits {
                max_work_upper_bound: exact_work,
                max_candidate_visits: accounting.candidate_visits,
                max_scratch_bytes: 0,
            };
            assert!(
                plan.is_match_window(haystack, Window::full(haystack), exact)
                    .unwrap()
                    .0
            );
            assert!(
                plan.is_match_window_value(haystack, Window::full(haystack), exact)
                    .unwrap()
            );

            let one_below = SearchLimits {
                max_work_upper_bound: exact_work - 1,
                max_candidate_visits: usize::MAX,
                max_scratch_bytes: 0,
            };
            let accounted = plan
                .is_match_window(haystack, Window::full(haystack), one_below)
                .unwrap_err();
            let value = plan
                .is_match_window_value(haystack, Window::full(haystack), one_below)
                .unwrap_err();
            assert_eq!(accounted, value);
            assert!(matches!(
                accounted,
                SearchError::WorkLimit { needed, limit }
                    if needed == exact_work && limit == exact_work - 1
            ));

            let one_below_candidates = SearchLimits {
                max_work_upper_bound: u64::MAX,
                max_candidate_visits: accounting.candidate_visits - 1,
                max_scratch_bytes: 0,
            };
            let accounted = plan
                .is_match_window(
                    haystack,
                    Window::full(haystack),
                    one_below_candidates,
                )
                .unwrap_err();
            let value = plan
                .is_match_window_value(
                    haystack,
                    Window::full(haystack),
                    one_below_candidates,
                )
                .unwrap_err();
            assert_eq!(accounted, value);
            assert!(matches!(
                accounted,
                SearchError::CandidateLimit { needed, limit }
                    if needed == accounting.candidate_visits
                        && limit == accounting.candidate_visits - 1
            ));
        }
    }

    #[test]
    fn search_and_shortest_match_every_canonical_one_sided_shape() {
        let cases = [
            (
                LiteralClassRunLiteralPlan::build(
                    b"item",
                    [(b'0', b'2')].into_iter(),
                    b"",
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                r"item[0-2]+",
                b"!item01221!itemx".as_slice(),
            ),
            (
                LiteralClassRunLiteralPlan::build(
                    b"",
                    [(b'x', b'y')].into_iter(),
                    b"cd",
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                r"[xy]+cd",
                b"!xyyxcd!xcd".as_slice(),
            ),
            (
                LiteralClassRunLiteralPlan::build(
                    b"",
                    [(b'a', b'b')].into_iter(),
                    b"aba",
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                r"[ab]+aba",
                b"!aababa!".as_slice(),
            ),
        ];
        for (plan, pattern, haystack) in cases {
            let oracle = RegexBuilder::new(pattern).unicode(false).build().unwrap();
            let selected = plan.find(haystack, SearchLimits::unlimited()).unwrap().0;
            let shortest = plan
                .shortest(haystack, SearchLimits::unlimited())
                .unwrap()
                .0;
            assert_eq!(
                selected,
                oracle
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end())),
                "pattern={pattern:?}"
            );
            assert_eq!(
                shortest,
                oracle.shortest_match(haystack),
                "pattern={pattern:?}"
            );
        }
    }

    #[test]
    fn exhaustive_small_haystacks_match_reference() {
        let plan = plan();
        let oracle = RegexBuilder::new(r"ab +cd").unicode(false).build().unwrap();
        let alphabet = [b'a', b'b', b' ', b'c', b'd', b'x'];
        for length in 0_usize..=7 {
            let cases = alphabet.len().pow(u32::try_from(length).unwrap());
            for mut ordinal in 0..cases {
                let mut haystack = vec![0; length];
                for byte in &mut haystack {
                    *byte = alphabet[ordinal % alphabet.len()];
                    ordinal /= alphabet.len();
                }
                let spans: Vec<_> = oracle
                    .find_iter(&haystack)
                    .map(|matched| matched.start()..matched.end())
                    .collect();
                let count = u64::try_from(spans.len()).unwrap();
                let sum = spans
                    .iter()
                    .map(|span| u64::try_from(span.end - span.start).unwrap())
                    .sum();
                assert_eq!(
                    plan.count(&haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .count,
                    count
                );
                assert_eq!(
                    plan.span_sum(&haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .span_sum,
                    sum
                );
            }
        }
    }

    #[test]
    fn complete_ascii_word_run_exhaustive_count_and_span_sum_match_regex_bytes() {
        let alphabet = [b'n', b'a', b'_', b'!', 0xff];
        for (suffix, pattern) in [
            (b"n".as_slice(), r"\b\w+n\b"),
            (b"nn".as_slice(), r"\b\w+nn\b"),
        ] {
            let plan = complete_ascii_word_run_plan(suffix);
            assert_eq!(
                plan.count_identity().boundary_semantics,
                BoundarySemantics::CompleteAsciiWordRun
            );
            assert_exhaustive_matches(&plan, pattern, &alphabet, 7);
        }
    }

    #[test]
    fn complete_ascii_word_run_overlap_boundaries_and_bounds_are_audited() {
        let plan = complete_ascii_word_run_plan(b"nn");
        for haystack in [
            b"".as_slice(),
            b"nn",
            b"nnn",
            b"!nnn!",
            b"_nn ",
            b"\xffann\x80nnn!",
            b"ann!bnn?nnnn.",
        ] {
            let (count, sum, _) = reference(r"\b\w+nn\b", haystack);
            let counted = plan.count(haystack, ReduceLimits::unlimited()).unwrap();
            let spanned = plan.span_sum(haystack, ReduceLimits::unlimited()).unwrap();
            assert_eq!(counted.count, count, "haystack={haystack:?}");
            assert_eq!(spanned.span_sum, sum, "haystack={haystack:?}");

            let input_bytes = haystack.len();
            let suffix_bytes = b"nn".len();
            let candidates = input_bytes
                .checked_sub(suffix_bytes)
                .map_or(0, |remaining| remaining + 1);
            let finder_service = input_bytes + candidates * (suffix_bytes - 1);
            assert_eq!(counted.accounting.upper_bounds.finder_calls, candidates);
            assert_eq!(
                counted.accounting.upper_bounds.finder_scanned_bytes,
                finder_service
            );
            assert_eq!(
                counted.accounting.upper_bounds.classifications,
                2 * candidates
            );
            assert_eq!(counted.accounting.upper_bounds.run_events, 0);
            assert_eq!(counted.accounting.actual.runs, 0);
            assert_eq!(counted.accounting.actual.literal_comparisons, 0);
            assert_eq!(
                counted.accounting.upper_bounds.match_events,
                input_bytes / (suffix_bytes + 1)
            );
            assert_eq!(counted.accounting.upper_bounds.span_sum, 0);
            assert_eq!(
                spanned.accounting.upper_bounds.classifications,
                input_bytes + candidates
            );
            assert_eq!(
                spanned.accounting.upper_bounds.span_sum,
                u64::try_from(input_bytes).unwrap()
            );
        }
    }

    #[test]
    fn complete_ascii_word_run_builder_revalidates_every_guard() {
        assert!(matches!(
            LiteralClassRunLiteralPlan::build_complete_ascii_word_run(
                b"x",
                ASCII_WORD_RANGES.into_iter(),
                b"n",
                BuildLimits::unlimited(),
            ),
            Err(BuildError::NonEmptyPrefixForCompleteAsciiWordRun)
        ));
        assert!(matches!(
            LiteralClassRunLiteralPlan::build_complete_ascii_word_run(
                b"",
                ASCII_WORD_RANGES.into_iter(),
                b"",
                BuildLimits::unlimited(),
            ),
            Err(BuildError::EmptySuffix)
        ));
        assert!(matches!(
            LiteralClassRunLiteralPlan::build_complete_ascii_word_run(
                b"",
                [(b'a', b'z')].into_iter(),
                b"n",
                BuildLimits::unlimited(),
            ),
            Err(BuildError::InexactAsciiWordClass)
        ));
        assert!(matches!(
            LiteralClassRunLiteralPlan::build_complete_ascii_word_run(
                b"",
                ASCII_WORD_RANGES.into_iter(),
                b"n-",
                BuildLimits::unlimited(),
            ),
            Err(BuildError::SuffixByteOutsideAsciiWordClass)
        ));
        let guarded = complete_ascii_word_run_plan(b"n");
        let unguarded = plan();
        assert_eq!(
            guarded.geometry,
            ResolvedSearchGeometry::CompleteAsciiWordSuffix
        );
        assert_eq!(unguarded.geometry, ResolvedSearchGeometry::GeneralPrefix);
        assert_eq!(
            guarded.boundary_semantics(),
            BoundarySemantics::CompleteAsciiWordRun
        );
        assert_eq!(
            guarded.count_identity().boundary_semantics,
            BoundarySemantics::CompleteAsciiWordRun
        );
        assert_eq!(
            unguarded.count_identity().boundary_semantics,
            BoundarySemantics::Unguarded
        );
        assert_eq!(guarded.count_identity().plan_id, PLAN_ID);
        assert_eq!(guarded.count_identity().operation_id, COUNT_OPERATION_ID);
    }

    #[test]
    fn ordinary_values_use_the_construction_resolved_route() {
        let direct = plan();
        reset_test_search_preflight_calls();
        assert!(direct
            .is_match_full_ordinary_value(b"!ab \tcd!")
            .unwrap());
        assert_eq!(test_search_preflight_calls(), 0);
        reset_test_search_preflight_calls();
        assert_eq!(
            direct
                .find_full_ordinary_value(b"!ab \tcd!")
                .unwrap(),
            Some((1, 7)),
        );
        assert_eq!(test_search_preflight_calls(), 0);

        let direct_suffix = LiteralClassRunLiteralPlan::build(
            b"a",
            [(b'x', b'x')].into_iter(),
            b"zz",
            BuildLimits::unlimited(),
        )
        .unwrap();
        reset_test_search_preflight_calls();
        assert!(direct_suffix
            .is_match_full_ordinary_value(b"!axxxzz!")
            .unwrap());
        assert_eq!(test_search_preflight_calls(), 0);
        reset_test_search_preflight_calls();
        assert_eq!(
            direct_suffix
                .find_full_ordinary_value(b"!axxxzz!")
                .unwrap(),
            Some((1, 7)),
        );
        assert_eq!(test_search_preflight_calls(), 0);

        let contained = LiteralClassRunLiteralPlan::build(
            b"",
            [(b'a', b'b')].into_iter(),
            b"aba",
            BuildLimits::unlimited(),
        )
        .unwrap();
        reset_test_search_preflight_calls();
        assert!(contained
            .is_match_full_ordinary_value(b"!aababa!")
            .unwrap());
        assert_eq!(test_search_preflight_calls(), 0);
        reset_test_search_preflight_calls();
        assert_eq!(
            contained
                .find_full_ordinary_value(b"!aababa!")
                .unwrap(),
            Some((1, 7)),
        );
        assert_eq!(test_search_preflight_calls(), 0);

        let guarded = complete_ascii_word_run_plan(b"ing");
        reset_test_search_preflight_calls();
        assert!(guarded
            .is_match_full_ordinary_value(b"!testing!")
            .unwrap());
        assert_eq!(test_search_preflight_calls(), 0);
        reset_test_search_preflight_calls();
        assert_eq!(
            guarded
                .find_full_ordinary_value(b"!testing!")
                .unwrap(),
            Some((1, 8)),
        );
        assert_eq!(test_search_preflight_calls(), 0);
    }

    #[test]
    fn contained_suffix_ordinary_values_match_incumbent_across_vector_boundaries() {
        let scalar = LiteralClassRunLiteralPlan::build(
            b"",
            [(b'a', b'c')].into_iter(),
            b"aba",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let dispatched = LiteralClassRunLiteralPlan::build_with_dispatch(
            SimdDispatchContext::capture(),
            b"",
            [(b'a', b'c')].into_iter(),
            b"aba",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let scanner = dispatched
            .ascii_scanner
            .as_ref()
            .expect("a dispatched ASCII plan retains one scanner");
        assert!(
            bounded_ascii_scanner_has_vector(Some(scanner)),
            "the boundary fixture must exercise a retained vector scanner",
        );

        let padding = ASCII_WIDE_BYTES;
        let backward_bytes = SIMD_SCALAR_PROOF_BYTES + ASCII_WIDE_BYTES + 3;
        let mut backward = vec![b'!'; padding];
        backward.extend(core::iter::repeat_n(b'c', backward_bytes));
        let suffix_start = backward.len();
        backward.extend_from_slice(b"ababa");
        let expected_end = backward.len();
        backward.extend(core::iter::repeat_n(b'!', ASCII_WIDE_BYTES));
        assert_eq!(
            scan_class_run_backward_value(
                &backward,
                dispatched.class,
                dispatched.ascii_scanner.as_ref(),
                suffix_start,
            ),
            Some(padding),
            "the first suffix follows a nonzero class run spanning the scalar proof and one full vector block",
        );
        let expected = Some((padding, expected_end));
        for candidate in [&scalar, &dispatched] {
            assert_eq!(
                candidate.find_full_ordinary_value(&backward).unwrap(),
                expected,
            );
            assert!(candidate
                .is_match_full_ordinary_value(&backward)
                .unwrap());
        }

        for run_bytes in 0..=100 {
            let mut haystack = vec![b'!'; ASCII_WIDE_BYTES];
            haystack.extend((0..run_bytes).map(|index| if index % 2 == 0 { b'a' } else { b'b' }));
            haystack.extend(core::iter::repeat_n(b'!', ASCII_WIDE_BYTES));

            let expected_find = scalar
                .find(&haystack, SearchLimits::unlimited())
                .unwrap()
                .0;
            let expected_exists = scalar
                .shortest(&haystack, SearchLimits::unlimited())
                .unwrap()
                .0
                .is_some();
            for candidate in [&scalar, &dispatched] {
                assert_eq!(
                    candidate.find_full_ordinary_value(&haystack).unwrap(),
                    expected_find,
                    "run length {run_bytes}",
                );
                assert_eq!(
                    candidate.is_match_full_ordinary_value(&haystack).unwrap(),
                    expected_exists,
                    "run length {run_bytes}",
                );
            }
        }
    }

    #[test]
    fn overlapping_prefix_anchor_candidates_are_not_skipped() {
        let plan = LiteralClassRunLiteralPlan::build(
            b"aaa",
            [(b'x', b'x')].into_iter(),
            b"b",
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(plan.geometry, ResolvedSearchGeometry::GeneralPrefix);
        assert_eq!(plan.anchor.needle(), b"aaa");
        let haystack = b"aaaaxxb--aaaxxb";
        let (_, _, spans) = reference(r"aaax+b", haystack);
        assert_eq!(spans, [1..7, 9..15]);
        assert_exhaustive_matches(&plan, r"aaax+b", b"abx", 9);
    }

    #[test]
    fn suffix_anchor_preserves_greedy_nonoverlap_and_overlap_restarts() {
        let plan = LiteralClassRunLiteralPlan::build(
            b"a",
            [(b'x', b'x')].into_iter(),
            b"aaaa",
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(plan.geometry, ResolvedSearchGeometry::GeneralSuffix);
        assert_eq!(plan.anchor.needle(), b"aaaa");
        for haystack in [
            b"axaaaaa".as_slice(),
            b"aaxaaaa".as_slice(),
            b"axaaaaxaaaa".as_slice(),
            b"axaaaaxxxaaaa".as_slice(),
            b"aaaaaxaaaa".as_slice(),
        ] {
            let (count, sum, _) = reference(r"ax+aaaa", haystack);
            assert_eq!(
                plan.count(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count,
                count,
                "haystack={haystack:?}"
            );
            assert_eq!(
                plan.span_sum(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .span_sum,
                sum,
                "haystack={haystack:?}"
            );
        }
        assert_exhaustive_matches(&plan, r"ax+aaaa", b"axy", 9);
    }

    #[test]
    fn one_sided_literal_anchors_preserve_greedy_nonoverlap() {
        let suffix_anchored = LiteralClassRunLiteralPlan::build(
            b"",
            [(b'a', b'z')].into_iter(),
            b"ing",
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(
            suffix_anchored.geometry,
            ResolvedSearchGeometry::SuffixInsideClass
        );
        assert_exhaustive_matches(&suffix_anchored, r"[a-z]+ing", b"aginx-", 6);

        let bordered_suffix = LiteralClassRunLiteralPlan::build(
            b"",
            [(b'a', b'a')].into_iter(),
            b"aa",
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_exhaustive_matches(&bordered_suffix, r"a+aa", b"ab-", 7);
        for (haystack, expected_count, expected_span_sum) in [
            (b"aa".as_slice(), 0, 0),
            (b"aaa".as_slice(), 1, 3),
            (b"aaaa".as_slice(), 1, 4),
            (b"aabaa".as_slice(), 0, 0),
            (b"aaaaa".as_slice(), 1, 5),
        ] {
            assert_eq!(
                bordered_suffix
                    .count(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count,
                expected_count
            );
            assert_eq!(
                bordered_suffix
                    .span_sum(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .span_sum,
                expected_span_sum
            );
        }

        let prefix_anchored = LiteralClassRunLiteralPlan::build(
            b"item",
            [(b'0', b'9')].into_iter(),
            b"",
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(
            prefix_anchored.geometry,
            ResolvedSearchGeometry::GeneralPrefix
        );
        assert_exhaustive_matches(&prefix_anchored, r"item[0-9]+", b"item012x", 6);

        let mixed_suffix = LiteralClassRunLiteralPlan::build(
            b"",
            [(b'a', b'a')].into_iter(),
            b"Xa",
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_exhaustive_matches(&mixed_suffix, r"a+Xa", b"aX-", 7);

        let mixed_suffix_wide_class = LiteralClassRunLiteralPlan::build(
            b"",
            [(b'a', b'b')].into_iter(),
            b"Xa",
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_exhaustive_matches(&mixed_suffix_wide_class, r"[ab]+Xa", b"abX-", 7);

        let digit_suffix = LiteralClassRunLiteralPlan::build(
            b"",
            [(b'0', b'9')].into_iter(),
            b"X5",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let haystack = b"1X567X5";
        assert_eq!(
            digit_suffix
                .count(haystack, ReduceLimits::unlimited())
                .unwrap()
                .count,
            2
        );
        assert_eq!(
            digit_suffix
                .span_sum(haystack, ReduceLimits::unlimited())
                .unwrap()
                .span_sum,
            7
        );
    }

    #[test]
    fn a_literal_anchor_is_required() {
        assert!(matches!(
            LiteralClassRunLiteralPlan::build(
                b"",
                [(b'a', b'z')].into_iter(),
                b"",
                BuildLimits::unlimited(),
            ),
            Err(BuildError::MissingLiteralAnchor)
        ));
    }

    #[test]
    fn dispatched_forward_scan_matches_scalar_and_accounts_terminating_vector() {
        let scalar = LiteralClassRunLiteralPlan::build(
            b"A",
            [(b'x', b'x')].into_iter(),
            b"Z",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let dispatched = LiteralClassRunLiteralPlan::build_with_dispatch(
            SimdDispatchContext::capture(),
            b"A",
            [(b'x', b'x')].into_iter(),
            b"Z",
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(scalar.geometry, ResolvedSearchGeometry::GeneralPrefix);
        assert_eq!(
            dispatched.geometry,
            ResolvedSearchGeometry::GeneralPrefix
        );
        assert!(scalar.count_identity().class_scan.is_none());
        assert!(dispatched.count_identity().class_scan.is_some());
        let dispatched_scan = dispatched
            .count_identity()
            .class_scan
            .expect("an ASCII dispatched plan installs a class scanner");

        let mut haystack = vec![b'A'];
        haystack.extend(core::iter::repeat_n(b'x', 1_000));
        haystack.push(b'Z');
        haystack.extend(core::iter::repeat_n(b'q', 40));
        let scalar = scalar.count(&haystack, ReduceLimits::unlimited()).unwrap();
        let dispatched = dispatched
            .count(&haystack, ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(dispatched.count, scalar.count);
        assert_eq!(dispatched.count, 1);
        assert_eq!(scalar.accounting.actual.classifications, 1_001);
        match dispatched_scan {
            ClassScanIdentity::Run { .. } => assert!(
                (1_001..=1_017).contains(&dispatched.accounting.actual.classifications),
                "the selected run leaf must report its exact physical work"
            ),
            ClassScanIdentity::Fixed { .. } => {
                assert_eq!(dispatched.accounting.actual.classifications, 1_024);
            }
        }
        assert!(
            dispatched.accounting.actual.classifications
                <= dispatched.accounting.upper_bounds.classifications
        );
        assert!(
            dispatched.accounting.actual.source_reads
                <= dispatched.accounting.upper_bounds.source_reads
        );
        assert!(dispatched.accounting.actual.work <= dispatched.accounting.upper_bounds.work);
    }

    #[test]
    fn dispatched_backward_scan_matches_scalar_and_accounts_terminating_vector() {
        let scalar = LiteralClassRunLiteralPlan::build(
            b"A",
            [(b'x', b'x')].into_iter(),
            b"ZZ",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let dispatched = LiteralClassRunLiteralPlan::build_with_dispatch(
            SimdDispatchContext::capture(),
            b"A",
            [(b'x', b'x')].into_iter(),
            b"ZZ",
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(scalar.geometry, ResolvedSearchGeometry::GeneralSuffix);
        assert_eq!(
            dispatched.geometry,
            ResolvedSearchGeometry::GeneralSuffix
        );
        let dispatched_scan = dispatched
            .span_sum_identity()
            .class_scan
            .expect("an ASCII dispatched plan installs a class scanner");

        let mut haystack = vec![b'q'; 31];
        haystack.push(b'A');
        haystack.extend(core::iter::repeat_n(b'x', 1_000));
        haystack.extend_from_slice(b"ZZ");
        let scalar = scalar
            .span_sum(&haystack, ReduceLimits::unlimited())
            .unwrap();
        let dispatched = dispatched
            .span_sum(&haystack, ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(dispatched.span_sum, scalar.span_sum);
        assert_eq!(dispatched.span_sum, 1_003);
        assert_eq!(scalar.accounting.actual.classifications, 1_001);
        match dispatched_scan {
            ClassScanIdentity::Run { .. } => assert!(
                (1_001..=1_017).contains(&dispatched.accounting.actual.classifications),
                "the selected run leaf must report its exact physical work"
            ),
            ClassScanIdentity::Fixed { .. } => {
                assert_eq!(dispatched.accounting.actual.classifications, 1_024);
            }
        }
        assert!(
            dispatched.accounting.actual.classifications
                <= dispatched.accounting.upper_bounds.classifications
        );
        assert!(
            dispatched.accounting.actual.source_reads
                <= dispatched.accounting.upper_bounds.source_reads
        );
        assert!(dispatched.accounting.actual.work <= dispatched.accounting.upper_bounds.work);
    }

    #[test]
    fn dispatched_vector_boundaries_match_scalar_in_both_directions() {
        const RANGES: [(u8, u8); 3] = [(b'0', b'9'), (b'_', b'_'), (b'a', b'f')];
        const MEMBERS: [u8; 5] = [b'0', b'9', b'_', b'a', b'f'];

        let dispatch = SimdDispatchContext::capture();
        let scalar_forward = LiteralClassRunLiteralPlan::build(
            b"P",
            RANGES.into_iter(),
            b"Z",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let dispatched_forward = LiteralClassRunLiteralPlan::build_with_dispatch(
            dispatch,
            b"P",
            RANGES.into_iter(),
            b"Z",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let scalar_backward = LiteralClassRunLiteralPlan::build(
            b"P",
            RANGES.into_iter(),
            b"ZZ",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let dispatched_backward = LiteralClassRunLiteralPlan::build_with_dispatch(
            dispatch,
            b"P",
            RANGES.into_iter(),
            b"ZZ",
            BuildLimits::unlimited(),
        )
        .unwrap();

        for run_bytes in 0..=100 {
            let run: Vec<u8> = (0..run_bytes)
                .map(|index| MEMBERS[index % MEMBERS.len()])
                .collect();

            let mut forward = vec![b'P'];
            forward.extend_from_slice(&run);
            forward.push(b'Z');
            // Keep a complete vector readable after the terminating suffix so
            // run lengths 32..=63 and 64..=95 terminate at every SIMD lane.
            forward.extend(core::iter::repeat_n(b'!', ASCII_WIDE_BYTES));
            let scalar = scalar_forward
                .count(&forward, ReduceLimits::unlimited())
                .unwrap();
            let dispatched = dispatched_forward
                .count(&forward, ReduceLimits::unlimited())
                .unwrap();
            assert_eq!(
                dispatched.count, scalar.count,
                "forward run length {run_bytes}"
            );
            assert!(
                dispatched.accounting.actual.classifications
                    <= dispatched.accounting.upper_bounds.classifications
            );
            assert!(
                dispatched.accounting.actual.source_reads
                    <= dispatched.accounting.upper_bounds.source_reads
            );
            assert!(dispatched.accounting.actual.work <= dispatched.accounting.upper_bounds.work);

            let mut backward = vec![b'!'; ASCII_WIDE_BYTES];
            backward.push(b'P');
            backward.extend_from_slice(&run);
            backward.extend_from_slice(b"ZZ");
            let scalar = scalar_backward
                .span_sum(&backward, ReduceLimits::unlimited())
                .unwrap();
            let dispatched = dispatched_backward
                .span_sum(&backward, ReduceLimits::unlimited())
                .unwrap();
            assert_eq!(
                dispatched.span_sum, scalar.span_sum,
                "backward run length {run_bytes}"
            );
            assert!(
                dispatched.accounting.actual.classifications
                    <= dispatched.accounting.upper_bounds.classifications
            );
            assert!(
                dispatched.accounting.actual.source_reads
                    <= dispatched.accounting.upper_bounds.source_reads
            );
            assert!(dispatched.accounting.actual.work <= dispatched.accounting.upper_bounds.work);
        }
    }

    #[test]
    fn dispatched_build_keeps_non_ascii_classes_on_exact_scalar_path() {
        let plan = LiteralClassRunLiteralPlan::build_with_dispatch(
            SimdDispatchContext::capture(),
            b"A",
            [(0x80, 0x80)].into_iter(),
            b"Z",
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert!(plan.count_identity().class_scan.is_none());
        assert_eq!(
            plan.count(b"A\x80\x80Z", ReduceLimits::unlimited())
                .unwrap()
                .count,
            1
        );
    }

    #[test]
    #[ignore = "manual release-mode paired scalar/forced-ISA no-regression measurement"]
    #[allow(
        clippy::too_many_lines,
        reason = "the ignored qualification keeps forward, backward, short-run, and build measurements under one identical paired timing harness"
    )]
    fn measure_dispatched_class_run_scans_against_scalar() {
        use fre_simd_kernels::{Feature, FeatureSet};
        use std::hint::black_box;
        use std::time::{Duration, Instant};

        fn measure(
            scenario: &str,
            policy: &str,
            variant: &str,
            batches: u32,
            calls_per_batch: u32,
            mut scalar: impl FnMut() -> u64,
            mut candidate: impl FnMut() -> u64,
        ) {
            let mut scalar_elapsed = Duration::ZERO;
            let mut candidate_elapsed = Duration::ZERO;
            let mut scalar_checksum = 0_u64;
            let mut candidate_checksum = 0_u64;
            for batch in 0..batches {
                let mut time_scalar = || {
                    let start = Instant::now();
                    for _ in 0..calls_per_batch {
                        scalar_checksum =
                            scalar_checksum.wrapping_add(black_box(scalar()).wrapping_add(1));
                    }
                    scalar_elapsed += start.elapsed();
                };
                let mut time_candidate = || {
                    let start = Instant::now();
                    for _ in 0..calls_per_batch {
                        candidate_checksum =
                            candidate_checksum.wrapping_add(black_box(candidate()).wrapping_add(1));
                    }
                    candidate_elapsed += start.elapsed();
                };
                if batch & 1 == 0 {
                    time_scalar();
                    time_candidate();
                } else {
                    time_candidate();
                    time_scalar();
                }
            }
            assert_eq!(scalar_checksum, candidate_checksum);
            eprintln!(
                "LITERAL_CLASS_RUN_BENCH scenario={scenario} policy={policy} \
                 variant={variant} scalar_ns={} candidate_ns={} candidate_over_scalar={:.6} \
                 checksum={candidate_checksum}",
                scalar_elapsed.as_nanos(),
                candidate_elapsed.as_nanos(),
                candidate_elapsed.as_secs_f64() / scalar_elapsed.as_secs_f64(),
            );
        }

        let dispatch = SimdDispatchContext::capture();
        let usable = dispatch.capabilities().usable();
        assert!(
            usable.contains(Feature::ArmSve) && usable.contains(Feature::ArmSve2),
            "this qualification benchmark requires an OS-usable SVE2 host"
        );
        let mut policies = vec![(
            "portable",
            DispatchPolicy::Portable,
            Some("ascii-byte-set.run.scalar.v1"),
        )];
        if usable.contains(Feature::ArmNeon) {
            policies.push((
                "neon",
                DispatchPolicy::AllowOnly(FeatureSet::of(Feature::ArmNeon)),
                Some("ascii-byte-set.run.neon.v1"),
            ));
        }
        if usable.contains(Feature::ArmSve) {
            policies.push((
                "sve",
                DispatchPolicy::AllowOnly(FeatureSet::of(Feature::ArmSve)),
                Some("ascii-byte-set.run.sve.v1"),
            ));
        }
        if usable.contains(Feature::ArmSve) && usable.contains(Feature::ArmSve2) {
            policies.push((
                "sve2",
                DispatchPolicy::AllowOnly(FeatureSet::of(Feature::ArmSve).with(Feature::ArmSve2)),
                Some("ascii-byte-set.run.sve2-match16.v1"),
            ));
        }
        policies.push(("auto", DispatchPolicy::Auto, None));

        let scalar_forward = LiteralClassRunLiteralPlan::build(
            b"A",
            [(b'x', b'x')].into_iter(),
            b"Z",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let mut forward_long = vec![b'A'];
        forward_long.extend(core::iter::repeat_n(b'x', (256 << 10) - 2));
        forward_long.push(b'Z');

        let scalar_backward = LiteralClassRunLiteralPlan::build(
            b"A",
            [(b'x', b'x')].into_iter(),
            b"ZZ",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let mut backward_long = vec![b'A'];
        backward_long.extend(core::iter::repeat_n(b'x', (256 << 10) - 3));
        backward_long.extend_from_slice(b"ZZ");

        let short_runs = b"AxZ!AxxZ!AxxxZ!AxxxxZ!".repeat(2_048);

        for (policy_name, policy, expected_variant) in policies {
            let candidate_forward = LiteralClassRunLiteralPlan::build_with_dispatch_policy(
                dispatch,
                policy,
                b"A",
                [(b'x', b'x')].into_iter(),
                b"Z",
                BuildLimits::unlimited(),
            )
            .unwrap();
            let candidate_backward = LiteralClassRunLiteralPlan::build_with_dispatch_policy(
                dispatch,
                policy,
                b"A",
                [(b'x', b'x')].into_iter(),
                b"ZZ",
                BuildLimits::unlimited(),
            )
            .unwrap();
            let ClassScanIdentity::Run {
                variant_id: variant,
            } = candidate_forward
                .count_identity()
                .class_scan
                .expect("an ASCII dispatched plan installs a run scanner")
            else {
                panic!("an SVE2 host must install the directional run scanner");
            };
            let ClassScanIdentity::Run {
                variant_id: backward_variant,
            } = candidate_backward
                .count_identity()
                .class_scan
                .expect("an ASCII dispatched plan installs a run scanner")
            else {
                panic!("an SVE2 host must install the directional run scanner");
            };
            assert_eq!(backward_variant, variant);
            if let Some(expected) = expected_variant {
                assert_eq!(variant, expected, "forced policy {policy_name}");
            }

            measure(
                "forward-long",
                policy_name,
                variant,
                16,
                4,
                || {
                    scalar_forward
                        .count(black_box(&forward_long), ReduceLimits::unlimited())
                        .unwrap()
                        .count
                },
                || {
                    candidate_forward
                        .count(black_box(&forward_long), ReduceLimits::unlimited())
                        .unwrap()
                        .count
                },
            );
            measure(
                "backward-long",
                policy_name,
                variant,
                16,
                4,
                || {
                    scalar_backward
                        .count(black_box(&backward_long), ReduceLimits::unlimited())
                        .unwrap()
                        .count
                },
                || {
                    candidate_backward
                        .count(black_box(&backward_long), ReduceLimits::unlimited())
                        .unwrap()
                        .count
                },
            );
            measure(
                "forward-short-runs",
                policy_name,
                variant,
                32,
                8,
                || {
                    scalar_forward
                        .count(black_box(&short_runs), ReduceLimits::unlimited())
                        .unwrap()
                        .count
                },
                || {
                    candidate_forward
                        .count(black_box(&short_runs), ReduceLimits::unlimited())
                        .unwrap()
                        .count
                },
            );
            measure(
                "ascii-plan-build",
                policy_name,
                variant,
                16,
                256,
                || {
                    LiteralClassRunLiteralPlan::build(
                        black_box(b"A"),
                        [(b'x', b'x')].into_iter(),
                        black_box(b"Z"),
                        BuildLimits::unlimited(),
                    )
                    .unwrap()
                    .build_accounting()
                    .literal_bytes
                    .try_into()
                    .unwrap()
                },
                || {
                    LiteralClassRunLiteralPlan::build_with_dispatch_policy(
                        dispatch,
                        policy,
                        black_box(b"A"),
                        [(b'x', b'x')].into_iter(),
                        black_box(b"Z"),
                        BuildLimits::unlimited(),
                    )
                    .unwrap()
                    .build_accounting()
                    .literal_bytes
                    .try_into()
                    .unwrap()
                },
            );
        }
    }

    #[test]
    fn overlapping_anchors_with_internal_class_bytes_preserve_run_barriers() {
        let prefix_anchor = LiteralClassRunLiteralPlan::build(
            b"abca",
            [(b'b', b'b')].into_iter(),
            b"z",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let prefix_haystack = b"abcabcabbbz";
        let (_, _, prefix_spans) = reference(r"abcab+z", prefix_haystack);
        assert_eq!(prefix_spans.len(), 1);
        assert_eq!(prefix_spans[0], 3..11);
        let prefix_result = prefix_anchor
            .span_sum(prefix_haystack, ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(prefix_result.span_sum, 8);
        assert!(
            prefix_result.accounting.actual.classifications
                <= prefix_result.accounting.upper_bounds.classifications
        );

        let suffix_anchor = LiteralClassRunLiteralPlan::build(
            b"b",
            [(b'c', b'c')].into_iter(),
            b"abca",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let suffix_haystack = b"abcabca";
        let (_, _, suffix_spans) = reference(r"bc+abca", suffix_haystack);
        assert_eq!(suffix_spans.len(), 1);
        assert_eq!(suffix_spans[0], 1..7);
        let suffix_result = suffix_anchor
            .span_sum(suffix_haystack, ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(suffix_result.span_sum, 6);
        assert!(
            suffix_result.accounting.actual.classifications
                <= suffix_result.accounting.upper_bounds.classifications
        );
    }

    #[test]
    fn dense_overlapping_anchor_accounting_is_preflighted_exactly() {
        let plan = LiteralClassRunLiteralPlan::build(
            b"a",
            [(b'x', b'x')].into_iter(),
            b"aaaa",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let haystack = vec![b'a'; 4_096];
        let baseline = plan.span_sum(&haystack, ReduceLimits::unlimited()).unwrap();
        assert_eq!(baseline.span_sum, 0);
        let upper = baseline.accounting.upper_bounds;
        let actual = baseline.accounting.actual;
        assert_eq!(upper.anchor_candidates, haystack.len() - 3);
        assert_eq!(actual.anchor_candidates, haystack.len() - 3);
        assert_eq!(actual.finder_calls, actual.anchor_candidates);
        assert_eq!(
            actual.finder_scanned_bytes,
            actual.anchor_candidates * b"aaaa".len()
        );
        assert!(actual.finder_scanned_bytes <= upper.finder_scanned_bytes);
        assert!(actual.classifications <= upper.classifications);
        assert!(actual.source_reads <= upper.source_reads);
        assert!(actual.work <= upper.work);

        let exact = ReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_source_reads: upper.source_reads,
            max_work: upper.work,
            max_run_events: upper.run_events,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_scratch_bytes: upper.scratch_bytes,
            max_persistent_bytes: upper.persistent_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        assert_eq!(plan.span_sum(&haystack, exact).unwrap().span_sum, 0);

        let mut below = exact;
        below.max_source_reads -= 1;
        assert!(matches!(
            plan.span_sum(&haystack, below),
            Err(ReduceError::SourceReadsLimit { needed, limit })
                if needed == upper.source_reads && limit == upper.source_reads - 1
        ));
        below = exact;
        below.max_work -= 1;
        assert!(matches!(
            plan.span_sum(&haystack, below),
            Err(ReduceError::WorkLimit { needed, limit })
                if needed == upper.work && limit == upper.work - 1
        ));
    }

    #[test]
    fn contained_suffix_count_uses_grouped_prospective_bounds() {
        let plan = LiteralClassRunLiteralPlan::build(
            b"",
            [(b'a', b'z')].into_iter(),
            b"ing",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let haystack = b"ing-thing-inging-xxing-ing-aaaaingbbbbing";
        let baseline = plan.count(haystack, ReduceLimits::unlimited()).unwrap();
        let upper = baseline.accounting.upper_bounds;
        let actual = baseline.accounting.actual;
        assert_eq!(baseline.count, reference(r"[a-z]+ing", haystack).0);
        assert!(actual.finder_calls <= upper.finder_calls);
        assert!(actual.finder_scanned_bytes <= upper.finder_scanned_bytes);
        assert!(actual.anchor_candidates <= upper.anchor_candidates);
        assert!(actual.classifications <= upper.classifications);
        assert!(actual.runs <= upper.run_events);
        assert!(actual.work <= upper.work);

        let exact = ReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_source_reads: upper.source_reads,
            max_work: upper.work,
            max_run_events: upper.run_events,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_scratch_bytes: upper.scratch_bytes,
            max_persistent_bytes: upper.persistent_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        assert_eq!(plan.count(haystack, exact).unwrap().count, baseline.count);

        let mut below = exact;
        below.max_work -= 1;
        assert!(matches!(
            plan.count(haystack, below),
            Err(ReduceError::WorkLimit { needed, limit })
                if needed == upper.work && limit == upper.work - 1
        ));
    }

    #[test]
    fn build_accounting_and_every_nonzero_limit_are_exact() {
        assert_eq!(
            size_of::<ResolvedSearchGeometry>(),
            size_of::<Anchor>(),
            "cached route must replace, not enlarge, the retained discriminant"
        );
        let baseline = plan().build_accounting();
        let exact = BuildLimits {
            max_literal_bytes: baseline.literal_bytes,
            max_class_ranges: baseline.class_ranges,
            max_class_members: baseline.class_members,
            max_build_work: baseline.work_upper_bound,
            max_scratch_bytes: baseline.scratch_bytes,
            max_persistent_bytes: baseline.persistent_bytes,
            max_peak_bytes: baseline.peak_bytes,
        };
        assert_eq!(
            LiteralClassRunLiteralPlan::build(b"ab", RANGES.into_iter(), b"cd", exact)
                .unwrap()
                .build_accounting(),
            baseline
        );
        let mut below = exact;
        below.max_literal_bytes -= 1;
        assert!(matches!(
            LiteralClassRunLiteralPlan::build(b"ab", RANGES.into_iter(), b"cd", below),
            Err(BuildError::LiteralBytesLimit { .. })
        ));
        below = exact;
        below.max_class_ranges -= 1;
        assert!(matches!(
            LiteralClassRunLiteralPlan::build(b"ab", RANGES.into_iter(), b"cd", below),
            Err(BuildError::ClassRangesLimit { .. })
        ));
        below = exact;
        below.max_class_members -= 1;
        assert!(matches!(
            LiteralClassRunLiteralPlan::build(b"ab", RANGES.into_iter(), b"cd", below),
            Err(BuildError::ClassMembersLimit { .. })
        ));
        below = exact;
        below.max_build_work -= 1;
        assert!(matches!(
            LiteralClassRunLiteralPlan::build(b"ab", RANGES.into_iter(), b"cd", below),
            Err(BuildError::WorkLimit { .. })
        ));
        below = exact;
        below.max_persistent_bytes -= 1;
        assert!(matches!(
            LiteralClassRunLiteralPlan::build(b"ab", RANGES.into_iter(), b"cd", below),
            Err(BuildError::PersistentLimit { .. })
        ));
        below = exact;
        below.max_peak_bytes -= 1;
        assert!(matches!(
            LiteralClassRunLiteralPlan::build(b"ab", RANGES.into_iter(), b"cd", below),
            Err(BuildError::PeakLimit { .. })
        ));
    }

    #[test]
    fn execution_bounds_are_prospective_tight_and_actual_is_below_upper() {
        let plan = plan();
        let haystack = b"ab \tcd--ab  cd--x x x";
        let baseline = plan.span_sum(haystack, ReduceLimits::unlimited()).unwrap();
        let upper = baseline.accounting.upper_bounds;
        let exact = ReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_source_reads: upper.source_reads,
            max_work: upper.work,
            max_run_events: upper.run_events,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_scratch_bytes: upper.scratch_bytes,
            max_persistent_bytes: upper.persistent_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        let audited = plan.span_sum(haystack, exact).unwrap();
        assert_eq!(audited.span_sum, baseline.span_sum);
        assert!(audited.accounting.actual.source_reads <= upper.source_reads);
        assert!(audited.accounting.actual.classifications <= upper.classifications);
        assert!(audited.accounting.actual.literal_comparisons <= upper.literal_comparisons);
        assert!(audited.accounting.actual.runs <= upper.run_events);
        assert!(audited.accounting.actual.candidates <= upper.candidate_events);
        assert!(audited.accounting.actual.matches <= upper.match_events);
        assert!(audited.accounting.actual.count <= upper.count);
        assert!(audited.accounting.actual.span_sum <= upper.span_sum);
        assert!(audited.accounting.actual.work <= upper.work);

        let mut below = exact;
        below.max_input_bytes -= 1;
        assert!(matches!(
            plan.span_sum(haystack, below),
            Err(ReduceError::InputBytesLimit { .. })
        ));
        below = exact;
        below.max_source_reads -= 1;
        assert!(matches!(
            plan.span_sum(haystack, below),
            Err(ReduceError::SourceReadsLimit { .. })
        ));
        below = exact;
        below.max_work -= 1;
        assert!(matches!(
            plan.span_sum(haystack, below),
            Err(ReduceError::WorkLimit { .. })
        ));
        below = exact;
        below.max_run_events -= 1;
        assert!(matches!(
            plan.span_sum(haystack, below),
            Err(ReduceError::RunEventsLimit { .. })
        ));
        below = exact;
        below.max_match_events -= 1;
        assert!(matches!(
            plan.span_sum(haystack, below),
            Err(ReduceError::MatchEventsLimit { .. })
        ));
        below = exact;
        below.max_count -= 1;
        assert!(matches!(
            plan.span_sum(haystack, below),
            Err(ReduceError::CountLimit { .. })
        ));
        below = exact;
        below.max_span_sum -= 1;
        assert!(matches!(
            plan.span_sum(haystack, below),
            Err(ReduceError::SpanSumLimit { .. })
        ));
        below = exact;
        below.max_persistent_bytes -= 1;
        assert!(matches!(
            plan.span_sum(haystack, below),
            Err(ReduceError::PersistentLimit { .. })
        ));
        below = exact;
        below.max_peak_bytes -= 1;
        assert!(matches!(
            plan.span_sum(haystack, below),
            Err(ReduceError::PeakLimit { .. })
        ));
    }

    #[test]
    fn construction_rejects_noncanonical_and_ambiguous_boundaries() {
        assert!(matches!(
            LiteralClassRunLiteralPlan::build(
                b"ab",
                [(b'z', b'a')].into_iter(),
                b"cd",
                BuildLimits::unlimited()
            ),
            Err(BuildError::NonCanonicalClass)
        ));
        assert!(matches!(
            LiteralClassRunLiteralPlan::build(
                b"a",
                [(b'a', b'b')].into_iter(),
                b"c",
                BuildLimits::unlimited()
            ),
            Err(BuildError::PrefixBoundaryInClass)
        ));
        assert!(matches!(
            LiteralClassRunLiteralPlan::build(
                b"a",
                [(b'b', b'c')].into_iter(),
                b"b",
                BuildLimits::unlimited()
            ),
            Err(BuildError::SuffixBoundaryInClass)
        ));
    }

    #[test]
    fn overflow_is_refused_before_source_traversal() {
        let plan = plan();
        assert!(matches!(
            plan.preflight(usize::MAX, Operation::SpanSum, ReduceLimits::unlimited(),),
            Err(ReduceError::ArithmeticOverflow { .. })
        ));
    }

    #[test]
    fn build_attempt_reports_exact_success_and_partial_failure() {
        let attempt = LiteralClassRunLiteralPlan::build_attempt(
            b"ab",
            RANGES.into_iter(),
            b"cd",
            BuildLimits::unlimited(),
        )
        .unwrap();
        let actual = attempt.actual();
        let (plan, returned_actual) = attempt.into_parts();
        let build = plan.build_accounting();
        assert_eq!(returned_actual, actual);
        assert_eq!(actual.work, u64::try_from(build.work_upper_bound).unwrap());
        assert_eq!(actual.allocations, 2);
        assert_eq!(actual.allocated_bytes, build.literal_bytes);
        assert_eq!(actual.copied_bytes, build.literal_bytes);
        assert_eq!(actual.initialized_bytes, build.persistent_bytes);
        assert_eq!(actual.live_persistent_bytes, build.persistent_bytes);
        assert_eq!(actual.peak_bytes, build.peak_bytes);

        let error = LiteralClassRunLiteralPlan::build_attempt(
            b"a",
            [(b'a', b'b')].into_iter(),
            b"c",
            BuildLimits::unlimited(),
        )
        .unwrap_err();
        assert!(matches!(error.source(), BuildError::PrefixBoundaryInClass));
        assert_eq!(error.actual().work, 62);
        assert_eq!(error.actual().allocations, 0);
        assert_eq!(error.actual().allocated_bytes, 0);
        assert_eq!(error.actual().copied_bytes, 0);
        assert_eq!(error.actual().initialized_bytes, 0);
        assert_eq!(error.actual().live_persistent_bytes, 0);
        assert_eq!(error.actual().peak_bytes, 0);
    }
}
