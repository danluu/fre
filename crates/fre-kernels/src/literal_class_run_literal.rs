//! Whole-operation reduction for `LITERAL BYTE_CLASS+ LITERAL`.
//!
//! Admission proves that the byte immediately before and after the class run
//! is outside the class. Construction selects the longer fixed literal as a
//! native `memmem` anchor. Anchor occurrences are visited monotonically,
//! including overlaps; only their adjacent maximal class run and opposite
//! literal are checked. Prefix-anchor order is match-start order. For a suffix
//! anchor, the first suffix byte is a non-class barrier, so increasing suffix
//! order is also increasing maximal-run start order. Filtering starts behind
//! the preceding selected end therefore preserves greedy, leftmost-first,
//! non-overlapping Rust byte semantics without classifying unrelated bytes.
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

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all arithmetic affecting resources or indices is checked; bitmap shifts use proved 0..=63 operands"
)]

use core::{fmt, mem::size_of};

use fre_exact_alloc::CopyError;
use fre_simd_kernels::{
    ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD, ASCII_WIDE_BYTES, AsciiByteSet, AsciiByteSetClassifier,
    AsciiByteSetRunScanner, DispatchPolicy, Feature, SimdDispatchContext,
};
use memchr::memmem::{Finder, FinderBuilder};

use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError};

pub const PLAN_ID: &str = "literal-class-run-literal.maximal-byte-run.v2";
pub const COUNT_OPERATION_ID: &str = "literal-class-run-literal.count.unicode-off.v2";
pub const SPAN_SUM_OPERATION_ID: &str = "literal-class-run-literal.span-sum.unicode-off.v2";

const FIXED_BUILD_WORK: usize = 32;
const LITERAL_BUILD_WORK_PER_BYTE: usize = 4;
const FINDER_BUILD_WORK_PER_BYTE: usize = 4;
const ANCHOR_SELECTION_WORK: usize = 2;
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
    Run,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Count,
    SpanSum,
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
    pub class_ranges: usize,
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

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyPrefix,
    EmptySuffix,
    EmptyClass,
    NonCanonicalClass,
    PrefixBoundaryInClass,
    SuffixBoundaryInClass,
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
        let first = usize::from(start) >> 6;
        let last = usize::from(end) >> 6;
        for word in first..=last {
            work.charge(RANGE_WORD_WORK)?;
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

    const fn ascii_set(self) -> AsciiByteSet {
        AsciiByteSet::from_words([self.0[0], self.0[1]])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Anchor {
    Prefix,
    Suffix,
}

#[derive(Debug)]
pub struct LiteralClassRunLiteralPlan {
    anchor: Finder<'static>,
    opposite_literal: Box<[u8]>,
    anchor_kind: Anchor,
    class: ByteClass,
    ascii_scanner: Option<AsciiClassScanner>,
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
        Self::build_attempt_inner(None, prefix, ranges, suffix, limits)
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
        Self::build_attempt_inner(Some((dispatch, policy)), prefix, ranges, suffix, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "construction keeps admission, exact allocation, optional classifier compilation, finder publication, and the terminal receipt in one auditable transaction"
    )]
    fn build_attempt_inner<I>(
        dispatch: Option<(SimdDispatchContext, DispatchPolicy)>,
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
                        computation: "literal byte total",
                    })?;
            let anchor_kind = if prefix.len() >= suffix.len() {
                Anchor::Prefix
            } else {
                Anchor::Suffix
            };
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
            work.charge(2)?;
            if class.contains(*prefix.last().ok_or(BuildError::EmptyPrefix)?) {
                return Err(BuildError::PrefixBoundaryInClass);
            }
            if class.contains(*suffix.first().ok_or(BuildError::EmptySuffix)?) {
                return Err(BuildError::SuffixBoundaryInClass);
            }
            let ascii_scanner =
                build_ascii_scanner(dispatch.filter(|_| class.is_ascii()), class, &mut work)?;
            let work_upper_bound = work.used;

            let prefix = copy_literal(prefix, "prefix")?;
            record_literal_copy(&mut actual, prefix.len())?;
            let suffix = copy_literal(suffix, "suffix")?;
            record_literal_copy(&mut actual, suffix.len())?;
            let prefix_bytes = prefix.len();
            let suffix_bytes = suffix.len();
            let (anchor, opposite_literal) = match anchor_kind {
                Anchor::Prefix => (FinderBuilder::new().build_forward_owned(prefix), suffix),
                Anchor::Suffix => (FinderBuilder::new().build_forward_owned(suffix), prefix),
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
                anchor_kind,
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
            unicode: false,
            greedy: true,
            non_overlapping: true,
        }
    }

    fn prefix(&self) -> &[u8] {
        match self.anchor_kind {
            Anchor::Prefix => self.anchor.needle(),
            Anchor::Suffix => &self.opposite_literal,
        }
    }

    fn suffix(&self) -> &[u8] {
        match self.anchor_kind {
            Anchor::Prefix => &self.opposite_literal,
            Anchor::Suffix => self.anchor.needle(),
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
            Some(AsciiClassScanner::Run(_)) => ClassScanKind::Run,
            None => ClassScanKind::Scalar,
        };
        derive_reduce_upper_bounds(self.build, class_scan, input_bytes, operation)
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
            let candidate = match self.anchor_kind {
                Anchor::Prefix => self.prefix_anchor_candidate(
                    haystack,
                    anchor_start,
                    anchor_end,
                    restart,
                    &mut actual,
                )?,
                Anchor::Suffix => self.suffix_anchor_candidate(
                    haystack,
                    anchor_start,
                    anchor_end,
                    restart,
                    &mut actual,
                )?,
            };
            if let Some((start, end)) = candidate {
                actual.matches = checked_add(actual.matches, 1, "actual match count")?;
                actual.count =
                    actual
                        .count
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual count",
                        })?;
                if operation == Operation::SpanSum {
                    let width = end
                        .checked_sub(start)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual match width",
                        })?;
                    actual.span_sum = actual
                        .span_sum
                        .checked_add(u64::try_from(width).map_err(|_| {
                            ReduceError::ArithmeticOverflow {
                                computation: "actual match width as u64",
                            }
                        })?)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual span sum",
                        })?;
                }
                actual.work = checked_add(actual.work, MATCH_WORK, "actual match work")?;
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
        let Some(start) = run_start.checked_sub(self.prefix().len()) else {
            return Ok(None);
        };
        if start < restart {
            return Ok(None);
        }
        actual.candidates = checked_add(actual.candidates, 1, "actual candidate count")?;
        if !literal_equals(haystack, start, self.prefix(), actual)? {
            return Ok(None);
        }
        Ok(Some((start, anchor_end)))
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the source-free preflight keeps every finder, class, literal, result, and resource bound adjacent"
)]
fn derive_reduce_upper_bounds(
    build: BuildAccounting,
    class_scan: ClassScanKind,
    input_bytes: usize,
    operation: Operation,
) -> Result<ReduceUpperBounds, ReduceError> {
    let anchor_bytes = build.prefix_bytes.max(build.suffix_bytes);
    let opposite_literal_bytes = build.prefix_bytes.min(build.suffix_bytes);
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
                    computation: "nonempty anchor overlap width",
                })?,
        )
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "overlapping anchor finder service",
        })?;
    let finder_scanned_bytes =
        input_bytes
            .checked_add(repeated_anchor_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "complete anchor finder service",
            })?;
    let run_events = input_bytes / 2 + input_bytes % 2;
    let logical_classifications =
        input_bytes
            .checked_add(anchor_candidates)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "class run plus adjacent class probes",
            })?;
    let classifications = match class_scan {
        ClassScanKind::Run => logical_classifications
            .checked_add(
                anchor_candidates
                    .checked_mul(ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD)
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
        Operation::SpanSum => {
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

fn build_ascii_scanner(
    dispatch: Option<(SimdDispatchContext, DispatchPolicy)>,
    class: ByteClass,
    work: &mut BuildWork<'_>,
) -> Result<Option<AsciiClassScanner>, BuildError> {
    let Some((dispatch, policy)) = dispatch else {
        return Ok(None);
    };
    if dispatch.capabilities().usable().contains(Feature::ArmSve) {
        work.charge(SIMD_RUN_SCANNER_BUILD_WORK)?;
        return Ok(Some(AsciiClassScanner::Run(
            dispatch
                .ascii_byte_set_run_scanner(class.ascii_set(), policy)
                .expect("the caller supplied an authentic compatible dispatch policy"),
        )));
    }
    work.charge(SIMD_FIXED_CLASSIFIER_BUILD_WORK)?;
    Ok(Some(AsciiClassScanner::Fixed(
        dispatch
            .ascii_byte_set_classifier(class.ascii_set(), policy)
            .expect("the caller supplied an authentic compatible dispatch policy"),
    )))
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

    fn plan() -> LiteralClassRunLiteralPlan {
        LiteralClassRunLiteralPlan::build(
            b"ab",
            RANGES.into_iter(),
            b"cd",
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
    fn overlapping_prefix_anchor_candidates_are_not_skipped() {
        let plan = LiteralClassRunLiteralPlan::build(
            b"aaa",
            [(b'x', b'x')].into_iter(),
            b"b",
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(plan.anchor_kind, Anchor::Prefix);
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
        assert_eq!(plan.anchor_kind, Anchor::Suffix);
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
        assert_eq!(scalar.anchor_kind, Anchor::Prefix);
        assert_eq!(dispatched.anchor_kind, Anchor::Prefix);
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
        assert_eq!(scalar.anchor_kind, Anchor::Suffix);
        assert_eq!(dispatched.anchor_kind, Anchor::Suffix);
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
    fn build_accounting_and_every_nonzero_limit_are_exact() {
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
