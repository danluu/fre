//! Whole-operation reduction for `LITERAL BYTE_CLASS+ LITERAL`.
//!
//! Admission proves that the byte immediately before and after the class run
//! is outside the class. Therefore every match owns one maximal class run.
//! Enumerating those runs once, checking their immediate literal borders and
//! filtering starts behind the preceding selected end preserves greedy,
//! leftmost-first, non-overlapping Rust byte semantics.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all arithmetic affecting resources or indices is checked; bitmap shifts use proved 0..=63 operands"
)]

use core::{fmt, mem::size_of};

use fre_exact_alloc::CopyError;

pub const PLAN_ID: &str = "literal-class-run-literal.maximal-byte-run.v1";
pub const COUNT_OPERATION_ID: &str = "literal-class-run-literal.count.unicode-off.v1";
pub const SPAN_SUM_OPERATION_ID: &str = "literal-class-run-literal.span-sum.unicode-off.v1";

const FIXED_BUILD_WORK: usize = 32;
const LITERAL_BUILD_WORK_PER_BYTE: usize = 4;
const RANGE_BUILD_WORK: usize = 8;
const RANGE_WORD_WORK: usize = 4;
const FIXED_REDUCE_WORK: usize = 16;
const CLASSIFICATION_WORK: usize = 2;
const LITERAL_COMPARISON_WORK: usize = 2;
const RUN_WORK: usize = 12;
const MATCH_WORK: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub prefix_bytes: usize,
    pub suffix_bytes: usize,
    pub class_words: [u64; 4],
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

    fn insert_range(&mut self, start: u8, end: u8, work: &mut BuildWork) -> Result<(), BuildError> {
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
}

#[derive(Debug)]
pub struct LiteralClassRunLiteralPlan {
    prefix: Box<[u8]>,
    suffix: Box<[u8]>,
    class: ByteClass,
    build: BuildAccounting,
}

impl LiteralClassRunLiteralPlan {
    pub fn build<I>(
        prefix: &[u8],
        mut ranges: I,
        suffix: &[u8],
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
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
        enforce_build(
            literal_bytes,
            limits.max_literal_bytes,
            BuildResource::LiteralBytes,
        )?;
        let scratch_bytes = 0;
        let persistent_bytes =
            size_of::<Self>()
                .checked_add(literal_bytes)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "persistent bytes",
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
            .and_then(|value| value.checked_add(FIXED_BUILD_WORK))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "fixed plus literal build work",
            })?;
        let mut work = BuildWork::new(limits.max_build_work);
        work.charge(literal_work)?;
        let (class, class_ranges, class_members) = build_class(&mut ranges, limits, &mut work)?;
        work.charge(2)?;
        if class.contains(*prefix.last().ok_or(BuildError::EmptyPrefix)?) {
            return Err(BuildError::PrefixBoundaryInClass);
        }
        if class.contains(*suffix.first().ok_or(BuildError::EmptySuffix)?) {
            return Err(BuildError::SuffixBoundaryInClass);
        }

        let prefix = copy_literal(prefix, "prefix")?;
        let suffix = copy_literal(suffix, "suffix")?;
        let prefix_bytes = prefix.len();
        let suffix_bytes = suffix.len();
        Ok(Self {
            prefix,
            suffix,
            class,
            build: BuildAccounting {
                prefix_bytes,
                suffix_bytes,
                literal_bytes,
                class_ranges,
                class_members,
                work_upper_bound: work.used,
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
            unicode: false,
            greedy: true,
            non_overlapping: true,
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
        let upper = self.derive_upper_bounds(input_bytes, operation)?;
        enforce_upper_bounds(upper, limits)?;
        Ok(upper)
    }

    fn derive_upper_bounds(
        &self,
        input_bytes: usize,
        operation: Operation,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let run_events = input_bytes / 2 + input_bytes % 2;
        let literal_bytes = self.build.literal_bytes;
        let literal_reads =
            run_events
                .checked_mul(literal_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "run events times literal bytes",
                })?;
        let source_reads =
            input_bytes
                .checked_add(literal_reads)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "classification plus literal source reads",
                })?;
        let minimum_width =
            literal_bytes
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
        let work = input_bytes
            .checked_mul(CLASSIFICATION_WORK)
            .and_then(|value| {
                literal_reads
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
        let persistent_bytes = self.build.persistent_bytes;
        let peak_bytes = persistent_bytes;
        Ok(ReduceUpperBounds {
            input_bytes,
            source_reads,
            classifications: input_bytes,
            literal_comparisons: literal_reads,
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

    fn scan(
        &self,
        haystack: &[u8],
        operation: Operation,
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let mut actual = ReduceActualCounters {
            source_reads: 0,
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
        let mut position = 0_usize;
        let mut restart = 0_usize;
        while position < haystack.len() {
            let byte = read_classified(haystack, position, &mut actual)?;
            if !self.class.contains(byte) {
                position = position
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "nonclass cursor advance",
                    })?;
                continue;
            }
            let run_start = position;
            let run_end = scan_class_run(haystack, self.class, &mut position, &mut actual)?;
            actual.runs = checked_add(actual.runs, 1, "actual run count")?;
            actual.work = checked_add(actual.work, RUN_WORK, "actual run work")?;
            let Some((start, end)) =
                self.candidate_span(haystack, run_start, run_end, restart, &mut actual)?
            else {
                continue;
            };
            actual.matches = checked_add(actual.matches, 1, "actual match count")?;
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
        }
        actual.source_reads = actual
            .classifications
            .checked_add(actual.literal_comparisons)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual source reads",
            })?;
        verify_actual(actual, upper)?;
        Ok(actual)
    }

    fn candidate_span(
        &self,
        haystack: &[u8],
        run_start: usize,
        run_end: usize,
        restart: usize,
        actual: &mut ReduceActualCounters,
    ) -> Result<Option<(usize, usize)>, ReduceError> {
        let Some(start) = run_start.checked_sub(self.prefix.len()) else {
            return Ok(None);
        };
        let end =
            run_end
                .checked_add(self.suffix.len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "candidate end",
                })?;
        if start < restart || end > haystack.len() {
            return Ok(None);
        }
        actual.candidates = checked_add(actual.candidates, 1, "actual candidate count")?;
        if !literal_equals(haystack, start, &self.prefix, actual)?
            || !literal_equals(haystack, run_end, &self.suffix, actual)?
        {
            return Ok(None);
        }
        Ok(Some((start, end)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Count,
    SpanSum,
}

fn build_class<I>(
    ranges: &mut I,
    limits: BuildLimits,
    work: &mut BuildWork,
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

fn scan_class_run(
    haystack: &[u8],
    class: ByteClass,
    position: &mut usize,
    actual: &mut ReduceActualCounters,
) -> Result<usize, ReduceError> {
    *position = position
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "class cursor advance",
        })?;
    while *position < haystack.len() {
        let byte = read_classified(haystack, *position, actual)?;
        if !class.contains(byte) {
            break;
        }
        *position = position
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "class run cursor advance",
            })?;
    }
    let run_end = *position;
    if *position < haystack.len() {
        *position = position
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "known nonclass cursor advance",
            })?;
    }
    Ok(run_end)
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
    actual.classifications = checked_add(actual.classifications, 1, "actual classifications")?;
    actual.work = checked_add(actual.work, CLASSIFICATION_WORK, "classification work")?;
    Ok(byte)
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

struct BuildWork {
    used: usize,
    limit: usize,
}

impl BuildWork {
    const fn new(limit: usize) -> Self {
        Self { used: 0, limit }
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
            plan.preflight(usize::MAX, Operation::SpanSum, ReduceLimits::unlimited()),
            Err(ReduceError::ArithmeticOverflow { .. })
        ));
    }
}
