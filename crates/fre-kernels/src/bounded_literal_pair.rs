//! Whole-operation reduction for `L C{0,K} R | R C{0,K} L`.
//!
//! The two nonempty literals have distinct leading bytes. A monotone
//! `memchr2` stream therefore enumerates every possible match start exactly
//! once. At each start, the reducer checks only the finite `K`-byte class
//! horizon and tests the opposite literal from the farthest viable position
//! backwards. This preserves greedy repetition and global non-overlap with
//! constant operation state and no operation allocation.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "resource and index arithmetic is checked; bitmap shifts use proved 0..=63 operands"
)]

use core::{fmt, mem::size_of};

use fre_exact_alloc::{CopyError, ExactBoxOrUsize};
use fre_simd_kernels::{
    ASCII_NARROW_BYTES, AsciiByteSet, AsciiByteSetRunScanner, DispatchPolicy, Feature,
    SelectionReceipt, SimdDispatchContext,
};
use memchr::memchr2;

use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError};

pub const PLAN_ID: &str = "bounded-literal-pair.memchr2-finite-horizon.v1";
pub const COUNT_OPERATION_ID: &str = "bounded-literal-pair.count.unicode-off.v1";
pub const SPAN_SUM_OPERATION_ID: &str = "bounded-literal-pair.span-sum.unicode-off.v1";
/// Stable identity of allocation-free complete-span visitation.
pub const SPAN_VISIT_OPERATION_ID: &str = "bounded-literal-pair.span-visit.unicode-off.v1";

const FIXED_BUILD_WORK: usize = 32;
const LITERAL_BUILD_WORK_PER_BYTE: usize = 4;
const RANGE_BUILD_WORK: usize = 8;
const RANGE_WORD_WORK: usize = 4;
const FIXED_REDUCE_WORK: usize = 16;
const SCAN_BYTE_WORK: usize = 1;
const CANDIDATE_WORK: usize = 4;
const COMPARISON_WORK: usize = 2;
const CLASSIFICATION_WORK: usize = 2;
const SUFFIX_PROBE_WORK: usize = 3;
const MATCH_WORK: usize = 8;
const SIMD_RUN_SCANNER_BUILD_WORK: usize = 128 + 1 + 1;
const SIMD_RUN_SCANNER_MIN_GAP: u32 = 17;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub left_bytes: usize,
    pub right_bytes: usize,
    pub gap_max: u32,
    pub class_words: [u64; 4],
    pub unicode: bool,
    pub greedy: bool,
    pub non_overlapping: bool,
    pub topology: Topology,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Topology {
    SwappedLiteralEndpoints,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_literal_bytes: usize,
    pub max_class_ranges: usize,
    pub max_class_members: usize,
    pub max_gap_bound: u32,
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
            max_gap_bound: u32::MAX,
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
            max_gap_bound: 4096,
            max_build_work: 32 * 1024 * 1024,
            max_scratch_bytes: 0,
            max_persistent_bytes: 32 * 1024 * 1024,
            max_peak_bytes: 32 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub left_bytes: usize,
    pub right_bytes: usize,
    pub literal_bytes: usize,
    pub class_ranges: usize,
    pub class_members: usize,
    pub gap_max: u32,
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
    pub max_candidate_events: usize,
    pub max_suffix_probes: usize,
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
            max_candidate_events: usize::MAX,
            max_suffix_probes: usize::MAX,
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
            max_source_reads: 32 * 1024 * 1024 * 1024,
            max_work: 64 * 1024 * 1024 * 1024,
            max_candidate_events: 512 * 1024 * 1024,
            max_suffix_probes: 8 * 1024 * 1024 * 1024,
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
    pub candidate_scan_bytes: usize,
    pub prefix_comparisons: usize,
    /// Physical byte classifications, including SIMD recovery rescans.
    pub gap_classifications: usize,
    pub suffix_probes: usize,
    pub suffix_comparisons: usize,
    pub source_reads: usize,
    pub work: usize,
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
    pub candidate_scan_bytes: usize,
    pub prefix_comparisons: usize,
    /// Physical byte classifications, including SIMD recovery rescans.
    pub gap_classifications: usize,
    pub suffix_probes: usize,
    pub suffix_comparisons: usize,
    pub source_reads: usize,
    pub work: usize,
    pub candidates: usize,
    pub matches: usize,
    pub count: u64,
    pub span_sum: u64,
    pub scratch_bytes: usize,
}

impl ReduceActualCounters {
    const fn new() -> Self {
        Self {
            candidate_scan_bytes: 0,
            prefix_comparisons: 0,
            gap_classifications: 0,
            suffix_probes: 0,
            suffix_comparisons: 0,
            source_reads: 0,
            work: FIXED_REDUCE_WORK,
            candidates: 0,
            matches: 0,
            count: 0,
            span_sum: 0,
            scratch_bytes: 0,
        }
    }
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
    EmptyLiteral {
        role: &'static str,
    },
    SharedLeadingByte {
        byte: u8,
    },
    EmptyClass,
    NonCanonicalClass,
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
    GapLimit {
        needed: u32,
        limit: u32,
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
        match self {
            Self::EmptyLiteral { role } => write!(f, "{role} literal is empty"),
            Self::SharedLeadingByte { byte } => {
                write!(f, "literal leading bytes are not distinct: {byte:#04x}")
            }
            Self::EmptyClass => f.write_str("bounded gap class is empty"),
            Self::NonCanonicalClass => f.write_str("bounded gap class is not canonical"),
            Self::LiteralBytesLimit { needed, limit } => {
                write!(f, "literal bytes need {needed}, limit is {limit}")
            }
            Self::ClassRangesLimit { needed, limit } => {
                write!(f, "class ranges need {needed}, limit is {limit}")
            }
            Self::ClassMembersLimit { needed, limit } => {
                write!(f, "class members need {needed}, limit is {limit}")
            }
            Self::GapLimit { needed, limit } => {
                write!(f, "gap bound needs {needed}, limit is {limit}")
            }
            Self::WorkLimit { needed, limit } => {
                write!(f, "build work needs {needed}, limit is {limit}")
            }
            Self::ScratchLimit { needed, limit } => {
                write!(f, "build scratch needs {needed}, limit is {limit}")
            }
            Self::PersistentLimit { needed, limit } => {
                write!(f, "persistent bytes need {needed}, limit is {limit}")
            }
            Self::PeakLimit { needed, limit } => {
                write!(f, "peak bytes need {needed}, limit is {limit}")
            }
            Self::AllocationFailed { structure, bytes } => {
                write!(f, "allocation failed for {structure} ({bytes} bytes)")
            }
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow computing {computation}")
            }
        }
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
    CandidateEventsLimit {
        needed: usize,
        limit: usize,
    },
    SuffixProbesLimit {
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
        match self {
            Self::InputBytesLimit { needed, limit } => {
                limit_message(f, "input bytes", *needed, *limit)
            }
            Self::SourceReadsLimit { needed, limit } => {
                limit_message(f, "source reads", *needed, *limit)
            }
            Self::WorkLimit { needed, limit } => limit_message(f, "work", *needed, *limit),
            Self::CandidateEventsLimit { needed, limit } => {
                limit_message(f, "candidate events", *needed, *limit)
            }
            Self::SuffixProbesLimit { needed, limit } => {
                limit_message(f, "suffix probes", *needed, *limit)
            }
            Self::MatchEventsLimit { needed, limit } => {
                limit_message(f, "match events", *needed, *limit)
            }
            Self::CountLimit { needed, limit } => {
                write!(f, "count needs {needed}, limit is {limit}")
            }
            Self::SpanSumLimit { needed, limit } => {
                write!(f, "span sum needs {needed}, limit is {limit}")
            }
            Self::ScratchLimit { needed, limit } => {
                limit_message(f, "scratch bytes", *needed, *limit)
            }
            Self::PersistentLimit { needed, limit } => {
                limit_message(f, "persistent bytes", *needed, *limit)
            }
            Self::PeakLimit { needed, limit } => limit_message(f, "peak bytes", *needed, *limit),
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow computing {computation}")
            }
            Self::AccountingInvariant {
                resource,
                actual,
                upper,
            } => write!(
                f,
                "actual {resource} {actual} exceeds prospective upper bound {upper}"
            ),
        }
    }
}

impl std::error::Error for ReduceError {}

fn limit_message(
    f: &mut fmt::Formatter<'_>,
    resource: &str,
    needed: usize,
    limit: usize,
) -> fmt::Result {
    write!(f, "{resource} need {needed}, limit is {limit}")
}

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
        let first_word = usize::from(start) / 64;
        let last_word = usize::from(end) / 64;
        for word in first_word..=last_word {
            work.charge(RANGE_WORD_WORK)?;
            let low = if word == first_word {
                usize::from(start) % 64
            } else {
                0
            };
            let high = if word == last_word {
                usize::from(end) % 64
            } else {
                63
            };
            let low_mask = u64::MAX << low;
            let high_mask = u64::MAX >> (63 - high);
            self.0[word] |= low_mask & high_mask;
        }
        Ok(())
    }

    fn contains(self, byte: u8) -> bool {
        let index = usize::from(byte);
        self.0[index / 64] & (1_u64 << (index % 64)) != 0
    }

    fn ascii_set(self) -> Option<AsciiByteSet> {
        (self.0[2] == 0 && self.0[3] == 0).then(|| AsciiByteSet::from_words([self.0[0], self.0[1]]))
    }
}

#[derive(Debug)]
pub struct BoundedLiteralPairPlan {
    left: Box<[u8]>,
    right: Box<[u8]>,
    class: ByteClass,
    gap_max: u32,
    build: BuildAccounting,
    class_run_scanner: ExactBoxOrUsize<AsciiByteSetRunScanner>,
}

impl BoundedLiteralPairPlan {
    pub fn build<I>(
        left: &[u8],
        ranges: I,
        right: &[u8],
        gap_max: u32,
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_attempt(left, ranges, right, gap_max, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build while retaining exact successful or partial terminal effects.
    pub fn build_attempt<I>(
        left: &[u8],
        ranges: I,
        right: &[u8],
        gap_max: u32,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_attempt_inner(None, left, ranges, right, gap_max, limits)
    }

    /// Build with one caller-captured capability snapshot and retain an Auto
    /// directional scanner for an eligible bounded ASCII class run.
    pub fn build_with_dispatch<I>(
        dispatch: SimdDispatchContext,
        left: &[u8],
        ranges: I,
        right: &[u8],
        gap_max: u32,
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_attempt_with_dispatch(dispatch, left, ranges, right, gap_max, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build the dispatched route while retaining exact successful or partial
    /// terminal effects.
    pub fn build_attempt_with_dispatch<I>(
        dispatch: SimdDispatchContext,
        left: &[u8],
        ranges: I,
        right: &[u8],
        gap_max: u32,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_attempt_inner(
            Some((dispatch, DispatchPolicy::Auto)),
            left,
            ranges,
            right,
            gap_max,
            limits,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "construction keeps proof checks, exact optional scanner retention, literal allocations, and terminal effects in one transaction"
    )]
    fn build_attempt_inner<I>(
        dispatch: Option<(SimdDispatchContext, DispatchPolicy)>,
        left: &[u8],
        mut ranges: I,
        right: &[u8],
        gap_max: u32,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        let mut actual = DirectBuildAttemptActual::default();
        let result = (|| {
            validate_literals(left, right, gap_max, limits)?;
            let literal_bytes =
                left.len()
                    .checked_add(right.len())
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "literal byte total",
                    })?;
            enforce_build_usize(
                literal_bytes,
                limits.max_literal_bytes,
                BuildResource::LiteralBytes,
            )?;
            let base_persistent_bytes = size_of::<Self>().checked_add(literal_bytes).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "persistent bytes",
                },
            )?;
            let scratch_bytes = 0;
            let base_peak_bytes = base_persistent_bytes;
            enforce_build_usize(
                scratch_bytes,
                limits.max_scratch_bytes,
                BuildResource::Scratch,
            )?;
            enforce_build_usize(
                base_persistent_bytes,
                limits.max_persistent_bytes,
                BuildResource::Persistent,
            )?;
            enforce_build_usize(base_peak_bytes, limits.max_peak_bytes, BuildResource::Peak)?;

            let literal_work = literal_bytes
                .checked_mul(LITERAL_BUILD_WORK_PER_BYTE)
                .and_then(|value| value.checked_add(FIXED_BUILD_WORK))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "literal build work",
                })?;
            let mut work = BuildWork::new(limits.max_build_work, &mut actual);
            work.charge(literal_work)?;
            let (class, class_ranges, class_members) = build_class(&mut ranges, limits, &mut work)?;
            let scanner_eligible = run_scanner_eligible(dispatch, class, gap_max);
            let scanner_bytes = usize::from(scanner_eligible)
                .checked_mul(size_of::<AsciiByteSetRunScanner>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "retained class-run scanner bytes",
                })?;
            let persistent_bytes = base_persistent_bytes.checked_add(scanner_bytes).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "persistent bytes with class-run scanner",
                },
            )?;
            let peak_bytes = persistent_bytes;
            enforce_build_usize(
                persistent_bytes,
                limits.max_persistent_bytes,
                BuildResource::Persistent,
            )?;
            enforce_build_usize(peak_bytes, limits.max_peak_bytes, BuildResource::Peak)?;
            work.charge(
                usize::from(scanner_eligible)
                    .checked_mul(SIMD_RUN_SCANNER_BUILD_WORK)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "class-run scanner build work",
                    })?,
            )?;
            let class_run_scanner = build_run_scanner(dispatch, class, gap_max);
            debug_assert_eq!(class_run_scanner.is_some(), scanner_eligible);
            let work_upper_bound = work.used;
            let left_owned = copy_literal(left, "left literal")?;
            record_literal_copy(&mut actual, left_owned.len())?;
            let right_owned = copy_literal(right, "right literal")?;
            record_literal_copy(&mut actual, right_owned.len())?;
            let class_run_scanner =
                retain_run_scanner(class_run_scanner).map_err(|error| match error {
                    CopyError::LayoutOverflow => BuildError::ArithmeticOverflow {
                        computation: "class-run scanner allocation layout",
                    },
                    CopyError::AllocationFailed => BuildError::AllocationFailed {
                        structure: "class-run scanner",
                        bytes: scanner_bytes,
                    },
                })?;
            if scanner_eligible {
                record_retained_value(&mut actual, scanner_bytes)?;
            }
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
                left: left_owned,
                right: right_owned,
                class,
                gap_max,
                build: BuildAccounting {
                    left_bytes: left.len(),
                    right_bytes: right.len(),
                    literal_bytes,
                    class_ranges,
                    class_members,
                    gap_max,
                    work_upper_bound,
                    scratch_bytes,
                    persistent_bytes,
                    peak_bytes,
                },
                class_run_scanner,
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

    /// Immutable Auto selection retained for the bounded ASCII class run.
    #[must_use]
    pub fn class_run_scanner_selection(&self) -> Option<SelectionReceipt> {
        self.class_run_scanner()
            .map(AsciiByteSetRunScanner::selection)
    }

    fn class_run_scanner(&self) -> Option<&AsciiByteSetRunScanner> {
        self.class_run_scanner.boxed()
    }

    #[cfg(test)]
    fn with_test_run_scanner(mut self) -> Self {
        let scanner = AsciiByteSetRunScanner::new(
            self.class
                .ascii_set()
                .expect("the test scanner requires one ASCII class"),
        );
        self.class_run_scanner =
            retain_run_scanner(Some(scanner)).expect("test scanner retention must allocate");
        let scanner_bytes = size_of::<AsciiByteSetRunScanner>();
        self.build.work_upper_bound = self
            .build
            .work_upper_bound
            .checked_add(SIMD_RUN_SCANNER_BUILD_WORK)
            .expect("test build work fits");
        self.build.persistent_bytes = self
            .build
            .persistent_bytes
            .checked_add(scanner_bytes)
            .expect("test persistent bytes fit");
        self.build.peak_bytes = self
            .build
            .peak_bytes
            .checked_add(scanner_bytes)
            .expect("test peak bytes fit");
        self
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
            left_bytes: self.build.left_bytes,
            right_bytes: self.build.right_bytes,
            gap_max: self.gap_max,
            class_words: self.class.0,
            unicode: false,
            greedy: true,
            non_overlapping: true,
            topology: Topology::SwappedLiteralEndpoints,
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

    /// Visit every complete non-overlapping match in one traversal. All
    /// prospective limits are checked before source access or the first
    /// callback.
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
        let actual = self.scan_with_visitor(haystack, Operation::SpanVisit, upper, &mut visitor)?;
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

    fn preflight(
        &self,
        input: usize,
        operation: Operation,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let upper = self.derive_upper_bounds(input, operation)?;
        enforce_upper_bounds(upper, limits)?;
        Ok(upper)
    }

    fn derive_upper_bounds(
        &self,
        input: usize,
        operation: Operation,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let candidates = input;
        let gap = usize::try_from(self.gap_max).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "gap bound as usize",
        })?;
        let literal_max = self.left.len().max(self.right.len());
        let prefix_comparisons =
            candidates
                .checked_mul(literal_max)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "prefix comparisons",
                })?;
        let scanner_recovery = self
            .class_run_scanner()
            .map_or(0, AsciiByteSetRunScanner::max_classification_overhead);
        let gap_classifications = gap
            .checked_add(scanner_recovery)
            .and_then(|per_candidate| candidates.checked_mul(per_candidate))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "physical gap classifications",
            })?;
        let probes_per_candidate = gap.checked_add(1).ok_or(ReduceError::ArithmeticOverflow {
            computation: "suffix probes per candidate",
        })?;
        let suffix_probes = candidates.checked_mul(probes_per_candidate).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "suffix probes",
            },
        )?;
        let suffix_comparisons =
            suffix_probes
                .checked_mul(literal_max)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "suffix comparisons",
                })?;
        let source_reads = input
            .checked_add(prefix_comparisons)
            .and_then(|value| value.checked_add(gap_classifications))
            .and_then(|value| value.checked_add(suffix_comparisons))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "source reads",
            })?;
        let minimum_width = self.left.len().checked_add(self.right.len()).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "minimum width",
            },
        )?;
        let matches = input / minimum_width;
        let count = u64::try_from(matches).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "match bound as u64",
        })?;
        let span_sum = if matches!(operation, Operation::SpanSum | Operation::SpanVisit) {
            u64::try_from(input).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "input as span sum",
            })?
        } else {
            0
        };
        let work = reduce_work(
            input,
            candidates,
            prefix_comparisons,
            gap_classifications,
            suffix_probes,
            suffix_comparisons,
            matches,
        )?;
        Ok(ReduceUpperBounds {
            input_bytes: input,
            candidate_scan_bytes: input,
            prefix_comparisons,
            gap_classifications,
            suffix_probes,
            suffix_comparisons,
            source_reads,
            work,
            candidate_events: candidates,
            match_events: matches,
            count,
            span_sum,
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.persistent_bytes,
        })
    }

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
        let mut actual = ReduceActualCounters::new();
        let mut position = 0_usize;
        while position < haystack.len() {
            let searched = &haystack[position..];
            let Some(relative) = memchr2(self.left[0], self.right[0], searched) else {
                charge_scan(&mut actual, searched.len())?;
                break;
            };
            charge_scan(
                &mut actual,
                relative
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "candidate scan hit bytes",
                    })?,
            )?;
            let start = position
                .checked_add(relative)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "candidate start",
                })?;
            actual.candidates = checked_add(actual.candidates, 1, "candidate events")?;
            actual.work = checked_add(actual.work, CANDIDATE_WORK, "candidate work")?;
            let (prefix, suffix) = if haystack[start] == self.left[0] {
                (&self.left[..], &self.right[..])
            } else {
                (&self.right[..], &self.left[..])
            };
            let next = start
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "failed candidate advance",
                })?;
            let Some(prefix_end) = start
                .checked_add(prefix.len())
                .filter(|&end| end <= haystack.len())
            else {
                position = next;
                continue;
            };
            if !literal_equals(haystack, start, prefix, ComparisonRole::Prefix, &mut actual)? {
                position = next;
                continue;
            }
            let max_gap = self.class_prefix(haystack, prefix_end, &mut actual)?;
            let Some(end) =
                Self::greedy_suffix(haystack, prefix_end, max_gap, suffix, &mut actual)?
            else {
                position = next;
                continue;
            };
            actual.matches = checked_add(actual.matches, 1, "matches")?;
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
                        computation: "match width",
                    })?;
                actual.span_sum = actual
                    .span_sum
                    .checked_add(u64::try_from(width).map_err(|_| {
                        ReduceError::ArithmeticOverflow {
                            computation: "match width as u64",
                        }
                    })?)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual span sum",
                    })?;
            }
            actual.work = checked_add(actual.work, MATCH_WORK, "match work")?;
            if operation == Operation::SpanVisit {
                visitor(CompleteSpan { start, end });
            }
            position = end;
        }
        actual.source_reads = actual
            .candidate_scan_bytes
            .checked_add(actual.prefix_comparisons)
            .and_then(|value| value.checked_add(actual.gap_classifications))
            .and_then(|value| value.checked_add(actual.suffix_comparisons))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual source reads",
            })?;
        verify_actual(actual, upper)?;
        Ok(actual)
    }

    fn class_prefix(
        &self,
        haystack: &[u8],
        start: usize,
        actual: &mut ReduceActualCounters,
    ) -> Result<usize, ReduceError> {
        let bound = usize::try_from(self.gap_max).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "gap bound as usize",
        })?;
        let available =
            haystack
                .len()
                .checked_sub(start)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "gap available bytes",
                })?;
        let limit = bound.min(available);
        let mut width = 0_usize;
        let scalar_limit = if self.class_run_scanner().is_some() {
            limit.min(ASCII_NARROW_BYTES)
        } else {
            limit
        };
        while width < scalar_limit {
            let position = start
                .checked_add(width)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "gap position",
                })?;
            charge_gap_classifications(actual, 1)?;
            if !self.class.contains(haystack[position]) {
                return Ok(width);
            }
            width = checked_add(width, 1, "gap width")?;
        }
        if width == limit {
            return Ok(width);
        }
        let scanner = self
            .class_run_scanner()
            .expect("a partial scalar proof requires one retained run scanner");
        let continuation_start =
            start
                .checked_add(width)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "gap scanner start",
                })?;
        let continuation_end = start
            .checked_add(limit)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "gap scanner end",
            })?;
        let continuation = haystack.get(continuation_start..continuation_end).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "gap scanner source",
            },
        )?;
        let scan_result = scanner.scan_forward(continuation);
        charge_gap_classifications(actual, scan_result.examined_bytes())?;
        width = width.checked_add(scan_result.member_run_len()).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "SIMD gap width",
            },
        )?;
        Ok(width)
    }

    fn greedy_suffix(
        haystack: &[u8],
        prefix_end: usize,
        max_gap: usize,
        suffix: &[u8],
        actual: &mut ReduceActualCounters,
    ) -> Result<Option<usize>, ReduceError> {
        for gap in (0..=max_gap).rev() {
            actual.suffix_probes = checked_add(actual.suffix_probes, 1, "suffix probes")?;
            actual.work = checked_add(actual.work, SUFFIX_PROBE_WORK, "suffix probe work")?;
            let start = prefix_end
                .checked_add(gap)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "suffix start",
                })?;
            let Some(end) = start
                .checked_add(suffix.len())
                .filter(|&end| end <= haystack.len())
            else {
                continue;
            };
            if literal_equals(haystack, start, suffix, ComparisonRole::Suffix, actual)? {
                return Ok(Some(end));
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Operation {
    Count,
    SpanSum,
    SpanVisit,
}

#[derive(Clone, Copy)]
enum ComparisonRole {
    Prefix,
    Suffix,
}

fn literal_equals(
    haystack: &[u8],
    start: usize,
    literal: &[u8],
    role: ComparisonRole,
    actual: &mut ReduceActualCounters,
) -> Result<bool, ReduceError> {
    for (offset, &expected) in literal.iter().enumerate() {
        let position = start
            .checked_add(offset)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "literal comparison position",
            })?;
        let byte = *haystack
            .get(position)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "literal comparison source",
            })?;
        match role {
            ComparisonRole::Prefix => {
                actual.prefix_comparisons =
                    checked_add(actual.prefix_comparisons, 1, "prefix comparisons")?;
            }
            ComparisonRole::Suffix => {
                actual.suffix_comparisons =
                    checked_add(actual.suffix_comparisons, 1, "suffix comparisons")?;
            }
        }
        actual.work = checked_add(actual.work, COMPARISON_WORK, "literal comparison work")?;
        if byte != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

fn charge_scan(actual: &mut ReduceActualCounters, bytes: usize) -> Result<(), ReduceError> {
    actual.candidate_scan_bytes =
        checked_add(actual.candidate_scan_bytes, bytes, "candidate scan bytes")?;
    let work = bytes
        .checked_mul(SCAN_BYTE_WORK)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "candidate scan work",
        })?;
    actual.work = checked_add(actual.work, work, "candidate scan work")?;
    Ok(())
}

fn charge_gap_classifications(
    actual: &mut ReduceActualCounters,
    bytes: usize,
) -> Result<(), ReduceError> {
    actual.gap_classifications = checked_add(
        actual.gap_classifications,
        bytes,
        "physical gap classifications",
    )?;
    let work = bytes
        .checked_mul(CLASSIFICATION_WORK)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "gap classification work",
        })?;
    actual.work = checked_add(actual.work, work, "gap classification work")?;
    Ok(())
}

fn reduce_work(
    input: usize,
    candidates: usize,
    prefix: usize,
    class: usize,
    probes: usize,
    suffix: usize,
    matches: usize,
) -> Result<usize, ReduceError> {
    let terms = [
        input.checked_mul(SCAN_BYTE_WORK),
        candidates.checked_mul(CANDIDATE_WORK),
        prefix.checked_mul(COMPARISON_WORK),
        class.checked_mul(CLASSIFICATION_WORK),
        probes.checked_mul(SUFFIX_PROBE_WORK),
        suffix.checked_mul(COMPARISON_WORK),
        matches.checked_mul(MATCH_WORK),
    ];
    let mut work = FIXED_REDUCE_WORK;
    for term in terms {
        work = work
            .checked_add(term.ok_or(ReduceError::ArithmeticOverflow {
                computation: "reduction work term",
            })?)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "complete reduction work",
            })?;
    }
    Ok(work)
}

fn validate_literals(
    left: &[u8],
    right: &[u8],
    gap_max: u32,
    limits: BuildLimits,
) -> Result<(), BuildError> {
    if left.is_empty() {
        return Err(BuildError::EmptyLiteral { role: "left" });
    }
    if right.is_empty() {
        return Err(BuildError::EmptyLiteral { role: "right" });
    }
    if left[0] == right[0] {
        return Err(BuildError::SharedLeadingByte { byte: left[0] });
    }
    if gap_max > limits.max_gap_bound {
        return Err(BuildError::GapLimit {
            needed: gap_max,
            limit: limits.max_gap_bound,
        });
    }
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
    let mut range_count = 0_usize;
    let mut members = 0_usize;
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
        range_count = range_count
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "class range count",
            })?;
        enforce_build_usize(
            range_count,
            limits.max_class_ranges,
            BuildResource::ClassRanges,
        )?;
        let width = usize::from(end)
            .checked_sub(usize::from(start))
            .and_then(|value| value.checked_add(1))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "class range width",
            })?;
        members = members
            .checked_add(width)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "class members",
            })?;
        enforce_build_usize(
            members,
            limits.max_class_members,
            BuildResource::ClassMembers,
        )?;
        class.insert_range(start, end, work)?;
        previous_end = Some(end);
    }
    if range_count == 0 {
        return Err(BuildError::EmptyClass);
    }
    Ok((class, range_count, members))
}

fn run_scanner_eligible(
    dispatch: Option<(SimdDispatchContext, DispatchPolicy)>,
    class: ByteClass,
    gap_max: u32,
) -> bool {
    gap_max >= SIMD_RUN_SCANNER_MIN_GAP
        && class.ascii_set().is_some()
        && dispatch
            .is_some_and(|(context, _)| context.capabilities().usable().contains(Feature::ArmSve))
}

fn build_run_scanner(
    dispatch: Option<(SimdDispatchContext, DispatchPolicy)>,
    class: ByteClass,
    gap_max: u32,
) -> Option<AsciiByteSetRunScanner> {
    if !run_scanner_eligible(dispatch, class, gap_max) {
        return None;
    }
    let (context, policy) = dispatch.expect("scanner eligibility requires a dispatch context");
    Some(
        context
            .ascii_byte_set_run_scanner(
                class
                    .ascii_set()
                    .expect("scanner eligibility proves one ASCII class"),
                policy,
            )
            .expect("the caller supplied an authentic compatible dispatch policy"),
    )
}

fn retain_run_scanner(
    scanner: Option<AsciiByteSetRunScanner>,
) -> Result<ExactBoxOrUsize<AsciiByteSetRunScanner>, CopyError> {
    match scanner {
        Some(scanner) => ExactBoxOrUsize::try_from_boxed(scanner),
        None => ExactBoxOrUsize::try_from_usize(0),
    }
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
    fn charge(&mut self, amount: usize) -> Result<(), BuildError> {
        let needed = self
            .used
            .checked_add(amount)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "build work",
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
                u64::try_from(amount).map_err(|_| BuildError::ArithmeticOverflow {
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

fn enforce_build_usize(
    needed: usize,
    limit: usize,
    resource: BuildResource,
) -> Result<(), BuildError> {
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

fn copy_literal(source: &[u8], structure: &'static str) -> Result<Box<[u8]>, BuildError> {
    fre_exact_alloc::copy_exact(source)
        .map(Vec::into_boxed_slice)
        .map_err(|error| match error {
            CopyError::LayoutOverflow => BuildError::ArithmeticOverflow {
                computation: "literal allocation layout",
            },
            CopyError::AllocationFailed => BuildError::AllocationFailed {
                structure,
                bytes: source.len(),
            },
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

fn record_retained_value(
    actual: &mut DirectBuildAttemptActual,
    bytes: usize,
) -> Result<(), BuildError> {
    actual.allocations =
        actual
            .allocations
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "retained value allocation count",
            })?;
    actual.allocated_bytes =
        actual
            .allocated_bytes
            .checked_add(bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "retained value allocated bytes",
            })?;
    actual.initialized_bytes =
        actual
            .initialized_bytes
            .checked_add(bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "retained value initialized bytes",
            })?;
    actual.live_persistent_bytes =
        actual
            .live_persistent_bytes
            .checked_add(bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "retained value live persistent bytes",
            })?;
    actual.peak_bytes = actual.peak_bytes.max(actual.live_persistent_bytes);
    Ok(())
}

fn enforce_upper_bounds(upper: ReduceUpperBounds, limits: ReduceLimits) -> Result<(), ReduceError> {
    for (needed, limit, resource) in [
        (
            upper.input_bytes,
            limits.max_input_bytes,
            ReduceResource::Input,
        ),
        (
            upper.source_reads,
            limits.max_source_reads,
            ReduceResource::Source,
        ),
        (upper.work, limits.max_work, ReduceResource::Work),
        (
            upper.candidate_events,
            limits.max_candidate_events,
            ReduceResource::Candidates,
        ),
        (
            upper.suffix_probes,
            limits.max_suffix_probes,
            ReduceResource::SuffixProbes,
        ),
        (
            upper.match_events,
            limits.max_match_events,
            ReduceResource::Matches,
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

#[derive(Clone, Copy)]
enum ReduceResource {
    Input,
    Source,
    Work,
    Candidates,
    SuffixProbes,
    Matches,
    Scratch,
    Persistent,
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
        ReduceResource::Input => ReduceError::InputBytesLimit { needed, limit },
        ReduceResource::Source => ReduceError::SourceReadsLimit { needed, limit },
        ReduceResource::Work => ReduceError::WorkLimit { needed, limit },
        ReduceResource::Candidates => ReduceError::CandidateEventsLimit { needed, limit },
        ReduceResource::SuffixProbes => ReduceError::SuffixProbesLimit { needed, limit },
        ReduceResource::Matches => ReduceError::MatchEventsLimit { needed, limit },
        ReduceResource::Scratch => ReduceError::ScratchLimit { needed, limit },
        ReduceResource::Persistent => ReduceError::PersistentLimit { needed, limit },
        ReduceResource::Peak => ReduceError::PeakLimit { needed, limit },
    })
}

fn verify_actual(
    actual: ReduceActualCounters,
    upper: ReduceUpperBounds,
) -> Result<(), ReduceError> {
    for (name, actual, upper) in [
        (
            "candidate scan bytes",
            actual.candidate_scan_bytes,
            upper.candidate_scan_bytes,
        ),
        (
            "prefix comparisons",
            actual.prefix_comparisons,
            upper.prefix_comparisons,
        ),
        (
            "gap classifications",
            actual.gap_classifications,
            upper.gap_classifications,
        ),
        ("suffix probes", actual.suffix_probes, upper.suffix_probes),
        (
            "suffix comparisons",
            actual.suffix_comparisons,
            upper.suffix_comparisons,
        ),
        ("source reads", actual.source_reads, upper.source_reads),
        ("work", actual.work, upper.work),
        ("candidates", actual.candidates, upper.candidate_events),
        ("matches", actual.matches, upper.match_events),
        ("scratch bytes", actual.scratch_bytes, upper.scratch_bytes),
    ] {
        verify(name, actual, upper)?;
    }
    verify("count", actual.count, upper.count)?;
    verify("span sum", actual.span_sum, upper.span_sum)
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

#[cfg(test)]
mod tests {
    use super::{
        BoundedLiteralPairPlan, BuildError, BuildLimits, CLASSIFICATION_WORK, CompleteSpan,
        Operation, ReduceError, ReduceLimits, SIMD_RUN_SCANNER_BUILD_WORK,
    };
    use fre_simd_kernels::AsciiByteSetRunScanner;

    fn plan() -> BoundedLiteralPairPlan {
        BoundedLiteralPairPlan::build(
            b"a",
            [(b'x', b'x')].into_iter(),
            b"b",
            2,
            BuildLimits::default(),
        )
        .unwrap()
    }

    fn long_plan() -> BoundedLiteralPairPlan {
        BoundedLiteralPairPlan::build(
            b"a",
            [(b'x', b'y')].into_iter(),
            b"b",
            64,
            BuildLimits::default(),
        )
        .unwrap()
    }

    fn reference(haystack: &[u8]) -> (u64, u64) {
        let mut at = 0_usize;
        let mut count = 0_u64;
        let mut sum = 0_u64;
        while at < haystack.len() {
            let mut selected = None;
            'starts: for start in at..haystack.len() {
                let branches = [
                    (b"a".as_slice(), b"b".as_slice()),
                    (b"b".as_slice(), b"a".as_slice()),
                ];
                for (prefix, suffix) in branches {
                    if !haystack[start..].starts_with(prefix) {
                        continue;
                    }
                    let prefix_end = start + prefix.len();
                    for gap in (0_usize..=2).rev() {
                        let suffix_start = prefix_end + gap;
                        if suffix_start > haystack.len()
                            || !haystack[prefix_end..suffix_start]
                                .iter()
                                .all(|&byte| byte == b'x')
                        {
                            continue;
                        }
                        if haystack[suffix_start..].starts_with(suffix) {
                            selected = Some((start, suffix_start + suffix.len()));
                            break 'starts;
                        }
                    }
                }
            }
            let Some((start, end)) = selected else {
                break;
            };
            count += 1;
            sum += u64::try_from(end - start).unwrap();
            at = end;
        }
        (count, sum)
    }

    fn reference_spans(haystack: &[u8]) -> Vec<CompleteSpan> {
        let mut at = 0_usize;
        let mut spans = Vec::new();
        while at < haystack.len() {
            let mut selected = None;
            'starts: for start in at..haystack.len() {
                for (prefix, suffix) in [
                    (b"a".as_slice(), b"b".as_slice()),
                    (b"b".as_slice(), b"a".as_slice()),
                ] {
                    if !haystack[start..].starts_with(prefix) {
                        continue;
                    }
                    let prefix_end = start + prefix.len();
                    for gap in (0_usize..=2).rev() {
                        let suffix_start = prefix_end + gap;
                        if suffix_start > haystack.len()
                            || !haystack[prefix_end..suffix_start]
                                .iter()
                                .all(|&byte| byte == b'x')
                        {
                            continue;
                        }
                        if haystack[suffix_start..].starts_with(suffix) {
                            selected = Some(CompleteSpan {
                                start,
                                end: suffix_start + suffix.len(),
                            });
                            break 'starts;
                        }
                    }
                }
            }
            let Some(span) = selected else {
                break;
            };
            at = span.end;
            spans.push(span);
        }
        spans
    }

    #[test]
    fn exhaustive_small_haystacks_match_greedy_reference() {
        let plan = plan();
        let alphabet = [b'a', b'b', b'x', b'y', b'\n'];
        for length in 0_u32..=7 {
            let total = alphabet.len().pow(length);
            for mut encoded in 0..total {
                let mut haystack = vec![0; usize::try_from(length).unwrap()];
                for byte in &mut haystack {
                    *byte = alphabet[encoded % alphabet.len()];
                    encoded /= alphabet.len();
                }
                let expected = reference(&haystack);
                assert_eq!(
                    plan.count(&haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .count,
                    expected.0,
                    "{haystack:?}"
                );
                assert_eq!(
                    plan.span_sum(&haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .span_sum,
                    expected.1,
                    "{haystack:?}"
                );
            }
        }
    }

    #[test]
    fn directed_greed_lf_and_restart_cases() {
        let plan = plan();
        for haystack in [
            b"axxbaxxb".as_slice(),
            b"bxxa--axb",
            b"ax\nxb",
            b"ab",
            b"ba",
            b"aaxxb",
        ] {
            let expected = reference(haystack);
            assert_eq!(
                plan.count(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count,
                expected.0
            );
            assert_eq!(
                plan.span_sum(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .span_sum,
                expected.1
            );
            let mut spans = Vec::new();
            let visited = plan
                .visit_spans(haystack, ReduceLimits::unlimited(), |span| spans.push(span))
                .unwrap();
            assert_eq!(spans, reference_spans(haystack));
            assert_eq!(visited.matches, spans.len());
            assert_eq!(visited.span_sum, expected.1);
            assert_eq!(visited.accounting.identity, plan.span_visit_identity());
        }
    }

    #[test]
    fn span_visit_refuses_before_the_first_callback() {
        let plan = plan();
        let haystack = b"axxb--bxxa";
        let upper = plan
            .visit_spans(haystack, ReduceLimits::unlimited(), |_| {})
            .unwrap()
            .accounting
            .upper_bounds;
        let mut callbacks = 0_usize;
        let error = plan
            .visit_spans(
                haystack,
                ReduceLimits {
                    max_span_sum: upper.span_sum - 1,
                    ..ReduceLimits::unlimited()
                },
                |_| callbacks += 1,
            )
            .unwrap_err();
        assert_eq!(callbacks, 0);
        assert!(matches!(error, ReduceError::SpanSumLimit { .. }));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one construction test closes dispatch selection, exact effects, identities, and one-below resource boundaries"
    )]
    fn dispatched_ascii_build_charges_one_exact_sve_scanner() {
        use fre_simd_kernels::{Feature, SimdDispatchContext};

        let dispatch = SimdDispatchContext::capture();
        let sve_usable = dispatch.capabilities().usable().contains(Feature::ArmSve);
        let baseline = BoundedLiteralPairPlan::build_attempt(
            b"a",
            [(b'x', b'y')].into_iter(),
            b"b",
            64,
            BuildLimits::default(),
        )
        .unwrap();
        let dispatched = BoundedLiteralPairPlan::build_attempt_with_dispatch(
            dispatch,
            b"a",
            [(b'x', b'y')].into_iter(),
            b"b",
            64,
            BuildLimits::default(),
        )
        .unwrap();
        let baseline_actual = baseline.actual();
        let baseline = baseline.into_plan();
        let dispatched_actual = dispatched.actual();
        let dispatched = dispatched.into_plan();
        assert_eq!(
            dispatched.class_run_scanner_selection().is_some(),
            sve_usable
        );
        if let Some(selection) = dispatched.class_run_scanner_selection() {
            assert_eq!(selection.policy, fre_simd_kernels::DispatchPolicy::Auto);
            assert_eq!(selection.selection_input_bytes, 16);
        }
        let scanner_work = usize::from(sve_usable) * SIMD_RUN_SCANNER_BUILD_WORK;
        let scanner_bytes = usize::from(sve_usable)
            * core::mem::size_of::<fre_simd_kernels::AsciiByteSetRunScanner>();
        let baseline_build = baseline.build_accounting();
        let dispatched_build = dispatched.build_accounting();
        assert_eq!(
            dispatched_build.work_upper_bound,
            baseline_build.work_upper_bound + scanner_work
        );
        assert_eq!(
            dispatched_build.persistent_bytes,
            baseline_build.persistent_bytes + scanner_bytes
        );
        assert_eq!(
            dispatched_build.peak_bytes,
            baseline_build.peak_bytes + scanner_bytes
        );
        assert_eq!(
            dispatched_actual.work,
            u64::try_from(dispatched_build.work_upper_bound).unwrap()
        );
        assert_eq!(
            dispatched_actual.allocations,
            baseline_actual.allocations + usize::from(sve_usable)
        );
        assert_eq!(
            dispatched_actual.allocated_bytes,
            baseline_actual.allocated_bytes + scanner_bytes
        );
        assert_eq!(dispatched_actual.copied_bytes, baseline_actual.copied_bytes);
        assert_eq!(
            dispatched_actual.initialized_bytes,
            dispatched_build.persistent_bytes
        );
        assert_eq!(
            dispatched_actual.live_persistent_bytes,
            dispatched_build.persistent_bytes
        );
        assert_eq!(dispatched_actual.peak_bytes, dispatched_build.peak_bytes);
        assert_eq!(dispatched.count_identity(), baseline.count_identity());
        assert_eq!(dispatched.span_sum_identity(), baseline.span_sum_identity());

        let rebuild = |limits| {
            BoundedLiteralPairPlan::build_with_dispatch(
                dispatch,
                b"a",
                [(b'x', b'y')].into_iter(),
                b"b",
                64,
                limits,
            )
        };
        assert!(
            rebuild(BuildLimits {
                max_build_work: dispatched_build.work_upper_bound,
                max_persistent_bytes: dispatched_build.persistent_bytes,
                max_peak_bytes: dispatched_build.peak_bytes,
                ..BuildLimits::default()
            })
            .is_ok()
        );
        assert!(matches!(
            rebuild(BuildLimits {
                max_build_work: dispatched_build.work_upper_bound - 1,
                ..BuildLimits::default()
            }),
            Err(BuildError::WorkLimit { needed, limit })
                if needed == dispatched_build.work_upper_bound
                    && limit == dispatched_build.work_upper_bound - 1
        ));
        assert!(matches!(
            rebuild(BuildLimits {
                max_persistent_bytes: dispatched_build.persistent_bytes - 1,
                ..BuildLimits::default()
            }),
            Err(BuildError::PersistentLimit { needed, limit })
                if needed == dispatched_build.persistent_bytes
                    && limit == dispatched_build.persistent_bytes - 1
        ));
        assert!(matches!(
            rebuild(BuildLimits {
                max_peak_bytes: dispatched_build.peak_bytes - 1,
                ..BuildLimits::default()
            }),
            Err(BuildError::PeakLimit { needed, limit })
                if needed == dispatched_build.peak_bytes
                    && limit == dispatched_build.peak_bytes - 1
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one differential closes count, span sum, physical classifications, and exact execution limits over the same run boundaries"
    )]
    fn retained_scanner_preserves_results_and_closes_physical_byte_limits() {
        let scalar = long_plan();
        let accelerated = long_plan().with_test_run_scanner();
        let mut long = Vec::new();
        long.push(b'a');
        long.extend(core::iter::repeat_n(b'x', 64));
        long.extend_from_slice(b"b--b");
        long.extend(core::iter::repeat_n(b'y', 63));
        long.push(b'a');
        for haystack in [
            long.as_slice(),
            b"axxxxxb",
            b"a\xFFb",
            b"ayyyyyyyyyyyyyyyyyb",
            b"",
        ] {
            let scalar_count = scalar.count(haystack, ReduceLimits::unlimited()).unwrap();
            let accelerated_count = accelerated
                .count(haystack, ReduceLimits::unlimited())
                .unwrap();
            assert_eq!(accelerated_count.count, scalar_count.count);
            assert_eq!(
                accelerated_count.accounting.identity,
                scalar_count.accounting.identity
            );
            assert!(
                accelerated_count.accounting.actual.gap_classifications
                    <= accelerated_count
                        .accounting
                        .upper_bounds
                        .gap_classifications
            );
            assert!(
                accelerated_count.accounting.actual.source_reads
                    <= accelerated_count.accounting.upper_bounds.source_reads
            );
            assert!(
                accelerated_count.accounting.actual.work
                    <= accelerated_count.accounting.upper_bounds.work
            );
            let recovery = haystack
                .len()
                .checked_mul(
                    accelerated
                        .class_run_scanner()
                        .map_or(0, AsciiByteSetRunScanner::max_classification_overhead),
                )
                .unwrap();
            assert_eq!(
                accelerated_count
                    .accounting
                    .upper_bounds
                    .gap_classifications,
                scalar_count.accounting.upper_bounds.gap_classifications + recovery
            );
            assert_eq!(
                accelerated_count.accounting.upper_bounds.source_reads,
                scalar_count.accounting.upper_bounds.source_reads + recovery
            );
            assert_eq!(
                accelerated_count.accounting.upper_bounds.work,
                scalar_count.accounting.upper_bounds.work
                    + recovery.checked_mul(CLASSIFICATION_WORK).unwrap()
            );
            let scalar_span = scalar
                .span_sum(haystack, ReduceLimits::unlimited())
                .unwrap();
            let accelerated_span = accelerated
                .span_sum(haystack, ReduceLimits::unlimited())
                .unwrap();
            assert_eq!(accelerated_span.span_sum, scalar_span.span_sum);
            assert_eq!(
                accelerated_span.accounting.identity,
                scalar_span.accounting.identity
            );
            assert!(
                accelerated_span.accounting.actual.gap_classifications
                    <= accelerated_span.accounting.upper_bounds.gap_classifications
            );
        }

        let result = accelerated.count(&long, ReduceLimits::unlimited()).unwrap();
        let upper = result.accounting.upper_bounds;
        let exact = ReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_source_reads: upper.source_reads,
            max_work: upper.work,
            max_candidate_events: upper.candidate_events,
            max_suffix_probes: upper.suffix_probes,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: u64::MAX,
            max_scratch_bytes: upper.scratch_bytes,
            max_persistent_bytes: upper.persistent_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        assert!(accelerated.count(&long, exact).is_ok());
        let mut below = exact;
        below.max_source_reads -= 1;
        assert!(matches!(
            accelerated.count(&long, below),
            Err(ReduceError::SourceReadsLimit { needed, limit })
                if needed == upper.source_reads && limit == upper.source_reads - 1
        ));
        let mut below = exact;
        below.max_work -= 1;
        assert!(matches!(
            accelerated.count(&long, below),
            Err(ReduceError::WorkLimit { needed, limit })
                if needed == upper.work && limit == upper.work - 1
        ));
    }

    #[test]
    fn dispatched_non_ascii_class_preserves_scalar_build_and_execution() {
        use fre_simd_kernels::SimdDispatchContext;

        let scalar = BoundedLiteralPairPlan::build(
            b"a",
            [(0x80, 0x80)].into_iter(),
            b"b",
            64,
            BuildLimits::default(),
        )
        .unwrap();
        let dispatched = BoundedLiteralPairPlan::build_with_dispatch(
            SimdDispatchContext::capture(),
            b"a",
            [(0x80, 0x80)].into_iter(),
            b"b",
            64,
            BuildLimits::default(),
        )
        .unwrap();
        assert!(dispatched.class_run_scanner_selection().is_none());
        assert_eq!(dispatched.build_accounting(), scalar.build_accounting());
        assert_eq!(dispatched.count_identity(), scalar.count_identity());
        assert_eq!(
            dispatched
                .count(b"a\x80\x80b", ReduceLimits::unlimited())
                .unwrap(),
            scalar
                .count(b"a\x80\x80b", ReduceLimits::unlimited())
                .unwrap()
        );
    }

    #[test]
    fn build_limits_are_exact_and_one_below() {
        let built = plan().build_accounting();
        let exact = BuildLimits {
            max_literal_bytes: built.literal_bytes,
            max_class_ranges: built.class_ranges,
            max_class_members: built.class_members,
            max_gap_bound: built.gap_max,
            max_build_work: built.work_upper_bound,
            max_scratch_bytes: built.scratch_bytes,
            max_persistent_bytes: built.persistent_bytes,
            max_peak_bytes: built.peak_bytes,
        };
        assert!(
            BoundedLiteralPairPlan::build(b"a", [(b'x', b'x')].into_iter(), b"b", 2, exact).is_ok()
        );
        let mut one = exact;
        one.max_literal_bytes -= 1;
        assert!(matches!(
            BoundedLiteralPairPlan::build(b"a", [(b'x', b'x')].into_iter(), b"b", 2, one),
            Err(BuildError::LiteralBytesLimit { .. })
        ));
        let mut one = exact;
        one.max_class_ranges -= 1;
        assert!(matches!(
            BoundedLiteralPairPlan::build(b"a", [(b'x', b'x')].into_iter(), b"b", 2, one),
            Err(BuildError::ClassRangesLimit { .. })
        ));
        let mut one = exact;
        one.max_class_members -= 1;
        assert!(matches!(
            BoundedLiteralPairPlan::build(b"a", [(b'x', b'x')].into_iter(), b"b", 2, one),
            Err(BuildError::ClassMembersLimit { .. })
        ));
        let mut one = exact;
        one.max_gap_bound -= 1;
        assert!(matches!(
            BoundedLiteralPairPlan::build(b"a", [(b'x', b'x')].into_iter(), b"b", 2, one),
            Err(BuildError::GapLimit { .. })
        ));
        let mut one = exact;
        one.max_build_work -= 1;
        assert!(matches!(
            BoundedLiteralPairPlan::build(b"a", [(b'x', b'x')].into_iter(), b"b", 2, one),
            Err(BuildError::WorkLimit { .. })
        ));
        let mut one = exact;
        one.max_persistent_bytes -= 1;
        assert!(matches!(
            BoundedLiteralPairPlan::build(b"a", [(b'x', b'x')].into_iter(), b"b", 2, one),
            Err(BuildError::PersistentLimit { .. })
        ));
        let mut one = exact;
        one.max_peak_bytes -= 1;
        assert!(matches!(
            BoundedLiteralPairPlan::build(b"a", [(b'x', b'x')].into_iter(), b"b", 2, one),
            Err(BuildError::PeakLimit { .. })
        ));
    }

    #[test]
    fn reduce_limits_are_exact_one_below_and_actual_is_bounded() {
        let plan = plan();
        let haystack = b"axxb--bxxa--ab";
        let result = plan.span_sum(haystack, ReduceLimits::unlimited()).unwrap();
        let upper = result.accounting.upper_bounds;
        let exact = ReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_source_reads: upper.source_reads,
            max_work: upper.work,
            max_candidate_events: upper.candidate_events,
            max_suffix_probes: upper.suffix_probes,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_scratch_bytes: upper.scratch_bytes,
            max_persistent_bytes: upper.persistent_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        assert!(plan.span_sum(haystack, exact).is_ok());
        let mut one = exact;
        one.max_input_bytes -= 1;
        assert!(matches!(
            plan.span_sum(haystack, one),
            Err(ReduceError::InputBytesLimit { .. })
        ));
        let mut one = exact;
        one.max_source_reads -= 1;
        assert!(matches!(
            plan.span_sum(haystack, one),
            Err(ReduceError::SourceReadsLimit { .. })
        ));
        let mut one = exact;
        one.max_work -= 1;
        assert!(matches!(
            plan.span_sum(haystack, one),
            Err(ReduceError::WorkLimit { .. })
        ));
        let mut one = exact;
        one.max_candidate_events -= 1;
        assert!(matches!(
            plan.span_sum(haystack, one),
            Err(ReduceError::CandidateEventsLimit { .. })
        ));
        let mut one = exact;
        one.max_suffix_probes -= 1;
        assert!(matches!(
            plan.span_sum(haystack, one),
            Err(ReduceError::SuffixProbesLimit { .. })
        ));
        let mut one = exact;
        one.max_match_events -= 1;
        assert!(matches!(
            plan.span_sum(haystack, one),
            Err(ReduceError::MatchEventsLimit { .. })
        ));
        let mut one = exact;
        one.max_count -= 1;
        assert!(matches!(
            plan.span_sum(haystack, one),
            Err(ReduceError::CountLimit { .. })
        ));
        let mut one = exact;
        one.max_span_sum -= 1;
        assert!(matches!(
            plan.span_sum(haystack, one),
            Err(ReduceError::SpanSumLimit { .. })
        ));
        let mut one = exact;
        one.max_persistent_bytes -= 1;
        assert!(matches!(
            plan.span_sum(haystack, one),
            Err(ReduceError::PersistentLimit { .. })
        ));
        let mut one = exact;
        one.max_peak_bytes -= 1;
        assert!(matches!(
            plan.span_sum(haystack, one),
            Err(ReduceError::PeakLimit { .. })
        ));
        assert!(result.accounting.actual.source_reads <= upper.source_reads);
        assert!(result.accounting.actual.work <= upper.work);
    }

    #[test]
    fn shape_refusals_and_overflow_precede_traversal() {
        assert!(matches!(
            BoundedLiteralPairPlan::build(
                b"",
                [(0, 1)].into_iter(),
                b"b",
                1,
                BuildLimits::default()
            ),
            Err(BuildError::EmptyLiteral { .. })
        ));
        assert!(matches!(
            BoundedLiteralPairPlan::build(
                b"a",
                [(0, 1)].into_iter(),
                b"also",
                1,
                BuildLimits::default()
            ),
            Err(BuildError::SharedLeadingByte { .. })
        ));
        let huge = BoundedLiteralPairPlan::build(
            b"a",
            [(b'x', b'x')].into_iter(),
            b"b",
            u32::MAX,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert!(matches!(
            huge.derive_upper_bounds(usize::MAX, Operation::SpanSum),
            Err(ReduceError::ArithmeticOverflow { .. })
        ));
    }

    #[test]
    fn build_attempt_reports_exact_success_and_partial_failure() {
        let attempt = BoundedLiteralPairPlan::build_attempt(
            b"a",
            [(b'x', b'x')].into_iter(),
            b"b",
            2,
            BuildLimits::default(),
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

        let error = BoundedLiteralPairPlan::build_attempt(
            b"a",
            [(b'z', b'a')].into_iter(),
            b"b",
            2,
            BuildLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(error.source(), BuildError::NonCanonicalClass));
        assert_eq!(error.actual().work, 49);
        assert_eq!(error.actual().allocations, 0);
        assert_eq!(error.actual().allocated_bytes, 0);
        assert_eq!(error.actual().copied_bytes, 0);
        assert_eq!(error.actual().initialized_bytes, 0);
        assert_eq!(error.actual().live_persistent_bytes, 0);
        assert_eq!(error.actual().peak_bytes, 0);
    }
}
