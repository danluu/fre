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

use fre_exact_alloc::CopyError;
use memchr::memchr2;

use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError};

pub const PLAN_ID: &str = "bounded-literal-pair.memchr2-finite-horizon.v1";
pub const COUNT_OPERATION_ID: &str = "bounded-literal-pair.count.unicode-off.v1";
pub const SPAN_SUM_OPERATION_ID: &str = "bounded-literal-pair.span-sum.unicode-off.v1";

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
}

#[derive(Debug)]
pub struct BoundedLiteralPairPlan {
    left: Box<[u8]>,
    right: Box<[u8]>,
    class: ByteClass,
    gap_max: u32,
    build: BuildAccounting,
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
            let persistent_bytes = size_of::<Self>().checked_add(literal_bytes).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "persistent bytes",
                },
            )?;
            let scratch_bytes = 0;
            let peak_bytes = persistent_bytes;
            enforce_build_usize(
                scratch_bytes,
                limits.max_scratch_bytes,
                BuildResource::Scratch,
            )?;
            enforce_build_usize(
                persistent_bytes,
                limits.max_persistent_bytes,
                BuildResource::Persistent,
            )?;
            enforce_build_usize(peak_bytes, limits.max_peak_bytes, BuildResource::Peak)?;

            let literal_work = literal_bytes
                .checked_mul(LITERAL_BUILD_WORK_PER_BYTE)
                .and_then(|value| value.checked_add(FIXED_BUILD_WORK))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "literal build work",
                })?;
            let mut work = BuildWork::new(limits.max_build_work, &mut actual);
            work.charge(literal_work)?;
            let (class, class_ranges, class_members) = build_class(&mut ranges, limits, &mut work)?;
            let work_upper_bound = work.used;
            let left_owned = copy_literal(left, "left literal")?;
            record_literal_copy(&mut actual, left_owned.len())?;
            let right_owned = copy_literal(right, "right literal")?;
            record_literal_copy(&mut actual, right_owned.len())?;
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
        let gap_classifications =
            candidates
                .checked_mul(gap)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "gap classifications",
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
        let span_sum = if operation == Operation::SpanSum {
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
            if operation == Operation::SpanSum {
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
        while width < limit {
            let position = start
                .checked_add(width)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "gap position",
                })?;
            actual.gap_classifications =
                checked_add(actual.gap_classifications, 1, "gap classifications")?;
            actual.work = checked_add(actual.work, CLASSIFICATION_WORK, "gap classification work")?;
            if !self.class.contains(haystack[position]) {
                break;
            }
            width = checked_add(width, 1, "gap width")?;
        }
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
        BoundedLiteralPairPlan, BuildError, BuildLimits, Operation, ReduceError, ReduceLimits,
    };

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
        }
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
