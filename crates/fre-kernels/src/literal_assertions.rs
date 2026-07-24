//! Whole-operation reduction for `(?m:^L)|(?m:L$)`.
//!
//! One monotone `memchr` stream enumerates every possible start byte. Exact
//! literal confirmation is followed by the ordered start-line/end-line
//! predicates. A rejected candidate advances by one byte, while an accepted
//! candidate advances by the complete literal width, preserving overlapping
//! discovery and global non-overlap without operation allocation.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all resource/index arithmetic is checked or follows an immediately proved slice bound"
)]

use core::{fmt, mem::size_of};

use fre_exact_alloc::CopyError;
use memchr::memchr;

pub const PLAN_ID: &str = "literal-assertions.memchr-start-or-end-line.v1";
pub const COUNT_OPERATION_ID: &str = "literal-assertions.count.byte-stable.v1";
pub const SPAN_SUM_OPERATION_ID: &str = "literal-assertions.span-sum.byte-stable.v1";

const FIXED_BUILD_WORK: usize = 8;
const LITERAL_BUILD_WORK_PER_BYTE: usize = 2;
const FIXED_REDUCE_WORK: usize = 8;
const SCAN_BYTE_WORK: usize = 1;
const CANDIDATE_WORK: usize = 2;
const LITERAL_COMPARISON_WORK: usize = 1;
const ASSERTION_CHECK_WORK: usize = 2;
const BOUNDARY_READ_WORK: usize = 1;
const MATCH_WORK: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Topology {
    StartLineLiteralOrLiteralEndLine,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub literal_bytes: usize,
    pub line_terminator: u8,
    pub topology: Topology,
    pub branch_ordered: bool,
    pub overlap_complete: bool,
    pub non_overlapping: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_literal_bytes: usize,
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
            max_build_work: 16 * 1024 * 1024,
            max_scratch_bytes: 0,
            max_persistent_bytes: 16 * 1024 * 1024,
            max_peak_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub literal_bytes: usize,
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
    pub max_candidate_scan_bytes: usize,
    pub max_literal_comparisons: usize,
    pub max_assertion_checks: usize,
    pub max_boundary_reads: usize,
    pub max_candidate_events: usize,
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
            max_candidate_scan_bytes: usize::MAX,
            max_literal_comparisons: usize::MAX,
            max_assertion_checks: usize::MAX,
            max_boundary_reads: usize::MAX,
            max_candidate_events: usize::MAX,
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
            max_candidate_scan_bytes: 512 * 1024 * 1024,
            max_literal_comparisons: 32 * 1024 * 1024 * 1024,
            max_assertion_checks: 1024 * 1024 * 1024,
            max_boundary_reads: 1024 * 1024 * 1024,
            max_candidate_events: 512 * 1024 * 1024,
            max_match_events: 64 * 1024 * 1024,
            max_count: 64 * 1024 * 1024,
            max_span_sum: u64::MAX,
            max_scratch_bytes: 0,
            max_persistent_bytes: 16 * 1024 * 1024,
            max_peak_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub input_bytes: usize,
    pub candidate_scan_bytes: usize,
    pub literal_comparisons: usize,
    pub assertion_checks: usize,
    pub boundary_reads: usize,
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
    pub literal_comparisons: usize,
    pub assertion_checks: usize,
    pub boundary_reads: usize,
    pub source_reads: usize,
    pub work: usize,
    pub candidates: usize,
    pub matches: usize,
    pub count: u64,
    pub span_sum: u64,
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
    EmptyLiteral,
    LiteralBytesLimit { needed: usize, limit: usize },
    WorkLimit { needed: usize, limit: usize },
    ScratchLimit { needed: usize, limit: usize },
    PersistentLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    AllocationFailed { bytes: usize },
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "literal-assertions construction failed: {self:?}"
        )
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
    CandidateScanBytesLimit {
        needed: usize,
        limit: usize,
    },
    LiteralComparisonsLimit {
        needed: usize,
        limit: usize,
    },
    AssertionChecksLimit {
        needed: usize,
        limit: usize,
    },
    BoundaryReadsLimit {
        needed: usize,
        limit: usize,
    },
    CandidateEventsLimit {
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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "literal-assertions reduction failed: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

#[derive(Debug)]
pub struct LiteralAssertionsPlan {
    literal: Box<[u8]>,
    line_terminator: u8,
    build: BuildAccounting,
}

impl LiteralAssertionsPlan {
    pub fn build(
        literal: &[u8],
        line_terminator: u8,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        if literal.is_empty() {
            return Err(BuildError::EmptyLiteral);
        }
        enforce_build(
            literal.len(),
            limits.max_literal_bytes,
            BuildResource::LiteralBytes,
        )?;
        let work_upper_bound = literal
            .len()
            .checked_mul(LITERAL_BUILD_WORK_PER_BYTE)
            .and_then(|work| work.checked_add(FIXED_BUILD_WORK))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "literal build work",
            })?;
        enforce_build(work_upper_bound, limits.max_build_work, BuildResource::Work)?;
        let scratch_bytes = 0;
        let persistent_bytes =
            size_of::<Self>()
                .checked_add(literal.len())
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
        let literal = fre_exact_alloc::copy_exact(literal)
            .map(Vec::into_boxed_slice)
            .map_err(|error| match error {
                CopyError::LayoutOverflow => BuildError::ArithmeticOverflow {
                    computation: "exact literal allocation layout",
                },
                CopyError::AllocationFailed => BuildError::AllocationFailed {
                    bytes: literal.len(),
                },
            })?;
        Ok(Self {
            literal,
            line_terminator,
            build: BuildAccounting {
                literal_bytes: persistent_bytes - size_of::<Self>(),
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
            literal_bytes: self.build.literal_bytes,
            line_terminator: self.line_terminator,
            topology: Topology::StartLineLiteralOrLiteralEndLine,
            branch_ordered: true,
            overlap_complete: true,
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
        let candidate_events = if input_bytes < self.literal.len() {
            0
        } else {
            input_bytes
                .checked_sub(self.literal.len())
                .and_then(|remaining| remaining.checked_add(1))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "possible literal start positions",
                })?
        };
        let candidate_scan_bytes = candidate_events;
        let literal_comparisons = candidate_events.checked_mul(self.literal.len()).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "candidate literal comparisons",
            },
        )?;
        let assertion_checks =
            candidate_events
                .checked_mul(2)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "candidate assertion checks",
                })?;
        let boundary_reads = assertion_checks;
        let source_reads = candidate_scan_bytes
            .checked_add(literal_comparisons)
            .and_then(|reads| reads.checked_add(boundary_reads))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "complete source reads",
            })?;
        let match_events = input_bytes / self.literal.len();
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "match events as count",
        })?;
        let span_sum = match operation {
            Operation::Count => 0,
            Operation::SpanSum => {
                u64::try_from(input_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "input bytes as span-sum bound",
                })?
            }
        };
        let work = candidate_scan_bytes
            .checked_mul(SCAN_BYTE_WORK)
            .and_then(|value| {
                candidate_events
                    .checked_mul(CANDIDATE_WORK)
                    .and_then(|candidate| value.checked_add(candidate))
            })
            .and_then(|value| {
                literal_comparisons
                    .checked_mul(LITERAL_COMPARISON_WORK)
                    .and_then(|literal| value.checked_add(literal))
            })
            .and_then(|value| {
                assertion_checks
                    .checked_mul(ASSERTION_CHECK_WORK)
                    .and_then(|assertions| value.checked_add(assertions))
            })
            .and_then(|value| {
                boundary_reads
                    .checked_mul(BOUNDARY_READ_WORK)
                    .and_then(|reads| value.checked_add(reads))
            })
            .and_then(|value| {
                match_events
                    .checked_mul(MATCH_WORK)
                    .and_then(|matches| value.checked_add(matches))
            })
            .and_then(|value| value.checked_add(FIXED_REDUCE_WORK))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "complete reduction work",
            })?;
        let scratch_bytes = 0;
        let persistent_bytes = self.build.persistent_bytes;
        let peak_bytes = persistent_bytes;
        Ok(ReduceUpperBounds {
            input_bytes,
            candidate_scan_bytes,
            literal_comparisons,
            assertion_checks,
            boundary_reads,
            source_reads,
            work,
            candidate_events,
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
            candidate_scan_bytes: 0,
            literal_comparisons: 0,
            assertion_checks: 0,
            boundary_reads: 0,
            source_reads: 0,
            work: FIXED_REDUCE_WORK,
            candidates: 0,
            matches: 0,
            count: 0,
            span_sum: 0,
            scratch_bytes: 0,
        };
        if haystack.len() < self.literal.len() {
            verify_actual(actual, upper)?;
            return Ok(actual);
        }
        let last_start = haystack.len().checked_sub(self.literal.len()).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "last literal start",
            },
        )?;
        let first = *self
            .literal
            .first()
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "nonempty literal first byte",
            })?;
        let mut cursor = 0_usize;
        while cursor <= last_start {
            let search =
                haystack
                    .get(cursor..=last_start)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "candidate search window",
                    })?;
            let Some(relative) = memchr(first, search) else {
                charge_scan(&mut actual, search.len())?;
                break;
            };
            let scanned = relative
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "candidate scan progress",
                })?;
            charge_scan(&mut actual, scanned)?;
            let start = cursor
                .checked_add(relative)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "candidate absolute start",
                })?;
            let end =
                start
                    .checked_add(self.literal.len())
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "candidate end",
                    })?;
            actual.candidates = checked_add(actual.candidates, 1, "candidate events")?;
            actual.work = checked_add(actual.work, CANDIDATE_WORK, "candidate work")?;
            if literal_equals(haystack, start, &self.literal, &mut actual)?
                && self.assertions_match(haystack, start, end, &mut actual)?
            {
                record_match(&mut actual, operation, self.literal.len())?;
                cursor = end;
            } else {
                cursor = start
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "rejected candidate progress",
                    })?;
            }
        }
        actual.source_reads = actual
            .candidate_scan_bytes
            .checked_add(actual.literal_comparisons)
            .and_then(|reads| reads.checked_add(actual.boundary_reads))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual source reads",
            })?;
        verify_actual(actual, upper)?;
        Ok(actual)
    }

    fn assertions_match(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        actual: &mut ReduceActualCounters,
    ) -> Result<bool, ReduceError> {
        charge_assertion(actual)?;
        let start_line = if start == 0 {
            true
        } else {
            charge_boundary_read(actual)?;
            haystack
                .get(start - 1)
                .is_some_and(|&byte| byte == self.line_terminator)
        };
        if start_line {
            return Ok(true);
        }
        charge_assertion(actual)?;
        if end == haystack.len() {
            return Ok(true);
        }
        charge_boundary_read(actual)?;
        Ok(haystack
            .get(end)
            .is_some_and(|&byte| byte == self.line_terminator))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Count,
    SpanSum,
}

fn record_match(
    actual: &mut ReduceActualCounters,
    operation: Operation,
    match_width: usize,
) -> Result<(), ReduceError> {
    actual.matches = checked_add(actual.matches, 1, "match events")?;
    actual.count = actual
        .count
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "actual count",
        })?;
    if operation == Operation::SpanSum {
        actual.span_sum = actual
            .span_sum
            .checked_add(u64::try_from(match_width).map_err(|_| {
                ReduceError::ArithmeticOverflow {
                    computation: "literal width as u64",
                }
            })?)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual span sum",
            })?;
    }
    actual.work = checked_add(actual.work, MATCH_WORK, "match work")?;
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
            checked_add(actual.literal_comparisons, 1, "literal comparisons")?;
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

fn charge_scan(actual: &mut ReduceActualCounters, scanned: usize) -> Result<(), ReduceError> {
    actual.candidate_scan_bytes =
        checked_add(actual.candidate_scan_bytes, scanned, "candidate scan bytes")?;
    let work = scanned
        .checked_mul(SCAN_BYTE_WORK)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "candidate scan work",
        })?;
    actual.work = checked_add(actual.work, work, "candidate scan work")?;
    Ok(())
}

fn charge_assertion(actual: &mut ReduceActualCounters) -> Result<(), ReduceError> {
    actual.assertion_checks = checked_add(actual.assertion_checks, 1, "assertion checks")?;
    actual.work = checked_add(actual.work, ASSERTION_CHECK_WORK, "assertion check work")?;
    Ok(())
}

fn charge_boundary_read(actual: &mut ReduceActualCounters) -> Result<(), ReduceError> {
    actual.boundary_reads = checked_add(actual.boundary_reads, 1, "boundary reads")?;
    actual.work = checked_add(actual.work, BOUNDARY_READ_WORK, "boundary read work")?;
    Ok(())
}

fn verify_actual(
    actual: ReduceActualCounters,
    upper: ReduceUpperBounds,
) -> Result<(), ReduceError> {
    verify(
        "candidate scan bytes",
        actual.candidate_scan_bytes,
        upper.candidate_scan_bytes,
    )?;
    verify(
        "literal comparisons",
        actual.literal_comparisons,
        upper.literal_comparisons,
    )?;
    verify(
        "assertion checks",
        actual.assertion_checks,
        upper.assertion_checks,
    )?;
    verify(
        "boundary reads",
        actual.boundary_reads,
        upper.boundary_reads,
    )?;
    verify("source reads", actual.source_reads, upper.source_reads)?;
    verify("work", actual.work, upper.work)?;
    verify("candidates", actual.candidates, upper.candidate_events)?;
    verify("matches", actual.matches, upper.match_events)?;
    verify("count", actual.count, upper.count)?;
    verify("span sum", actual.span_sum, upper.span_sum)?;
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
            computation: "upper counter as u64",
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

#[derive(Clone, Copy)]
enum BuildResource {
    LiteralBytes,
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
        BuildResource::LiteralBytes => BuildError::LiteralBytesLimit { needed, limit },
        BuildResource::Work => BuildError::WorkLimit { needed, limit },
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
    CandidateScanBytes,
    LiteralComparisons,
    AssertionChecks,
    BoundaryReads,
    CandidateEvents,
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
            upper.candidate_scan_bytes,
            limits.max_candidate_scan_bytes,
            ReduceResource::CandidateScanBytes,
        ),
        (
            upper.literal_comparisons,
            limits.max_literal_comparisons,
            ReduceResource::LiteralComparisons,
        ),
        (
            upper.assertion_checks,
            limits.max_assertion_checks,
            ReduceResource::AssertionChecks,
        ),
        (
            upper.boundary_reads,
            limits.max_boundary_reads,
            ReduceResource::BoundaryReads,
        ),
        (
            upper.candidate_events,
            limits.max_candidate_events,
            ReduceResource::CandidateEvents,
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
        ReduceResource::CandidateScanBytes => {
            ReduceError::CandidateScanBytesLimit { needed, limit }
        }
        ReduceResource::LiteralComparisons => {
            ReduceError::LiteralComparisonsLimit { needed, limit }
        }
        ReduceResource::AssertionChecks => ReduceError::AssertionChecksLimit { needed, limit },
        ReduceResource::BoundaryReads => ReduceError::BoundaryReadsLimit { needed, limit },
        ReduceResource::CandidateEvents => ReduceError::CandidateEventsLimit { needed, limit },
        ReduceResource::MatchEvents => ReduceError::MatchEventsLimit { needed, limit },
        ReduceResource::Scratch => ReduceError::ScratchLimit { needed, limit },
        ReduceResource::Persistent => ReduceError::PersistentLimit { needed, limit },
        ReduceResource::Peak => ReduceError::PeakLimit { needed, limit },
    })
}

#[cfg(test)]
mod tests {
    use regex::bytes::RegexBuilder;

    use super::*;

    fn oracle(literal: &str, terminator: u8, haystack: &[u8]) -> (u64, u64) {
        let escaped = regex::escape(literal);
        let pattern = format!(r"(?m:^{escaped})|(?m:{escaped}$)");
        let regex = RegexBuilder::new(&pattern)
            .unicode(false)
            .line_terminator(terminator)
            .build()
            .unwrap();
        regex.find_iter(haystack).fold((0_u64, 0_u64), |sum, m| {
            (
                sum.0.checked_add(1).unwrap(),
                sum.1.checked_add(u64::try_from(m.len()).unwrap()).unwrap(),
            )
        })
    }

    fn generate(alphabet: &[u8], maximum: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        for _ in 0..maximum {
            let prior = all.clone();
            for prefix in prior {
                for &byte in alphabet {
                    let mut value = prefix.clone();
                    value.push(byte);
                    all.push(value);
                }
            }
        }
        all.sort();
        all.dedup();
        all
    }

    #[test]
    fn overlapping_rejected_candidate_does_not_hide_line_end_match() {
        let plan = LiteralAssertionsPlan::build(b"aaa", b'\n', BuildLimits::default()).unwrap();
        let haystack = b"xaaaa\n";
        let expected = oracle("aaa", b'\n', haystack);
        assert_eq!(expected, (1, 3));
        assert_eq!(
            plan.count(haystack, ReduceLimits::default()).unwrap().count,
            expected.0
        );
        assert_eq!(
            plan.span_sum(haystack, ReduceLimits::default())
                .unwrap()
                .span_sum,
            expected.1
        );
    }

    #[test]
    fn exhaustive_small_byte_stable_semantics_match_pinned_regex() {
        let haystacks = generate(&[b'\n', b'a', b'b', 0xFF], 5);
        for literal in ["a", "aa", "ab", "aba"] {
            let plan =
                LiteralAssertionsPlan::build(literal.as_bytes(), b'\n', BuildLimits::default())
                    .unwrap();
            for haystack in &haystacks {
                let expected = oracle(literal, b'\n', haystack);
                assert_eq!(
                    plan.count(haystack, ReduceLimits::default()).unwrap().count,
                    expected.0,
                    "literal={literal:?}, haystack={haystack:?}"
                );
                assert_eq!(
                    plan.span_sum(haystack, ReduceLimits::default())
                        .unwrap()
                        .span_sum,
                    expected.1,
                    "literal={literal:?}, haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    fn custom_terminator_invalid_bytes_and_branch_overlap_are_exact() {
        let plan = LiteralAssertionsPlan::build(b"ab", 0xFF, BuildLimits::default()).unwrap();
        let haystack = b"ab\xFFxab\xFFab";
        let expected = oracle("ab", 0xFF, haystack);
        assert_eq!(expected, (3, 6));
        let count = plan.count(haystack, ReduceLimits::default()).unwrap();
        let span = plan.span_sum(haystack, ReduceLimits::default()).unwrap();
        assert_eq!((count.count, span.span_sum), expected);
        assert_eq!(count.accounting.identity.line_terminator, 0xFF);
        assert!(count.accounting.identity.overlap_complete);
    }

    #[test]
    fn build_and_reduce_limits_are_exact_and_preflighted() {
        let exact = LiteralAssertionsPlan::build(b"needle", b'\n', BuildLimits::default())
            .unwrap()
            .build_accounting();
        for limits in [
            BuildLimits {
                max_literal_bytes: exact.literal_bytes - 1,
                ..BuildLimits::default()
            },
            BuildLimits {
                max_build_work: exact.work_upper_bound - 1,
                ..BuildLimits::default()
            },
            BuildLimits {
                max_persistent_bytes: exact.persistent_bytes - 1,
                ..BuildLimits::default()
            },
            BuildLimits {
                max_peak_bytes: exact.peak_bytes - 1,
                ..BuildLimits::default()
            },
        ] {
            assert!(LiteralAssertionsPlan::build(b"needle", b'\n', limits).is_err());
        }

        let plan = LiteralAssertionsPlan::build(b"needle", b'\n', BuildLimits::default()).unwrap();
        let haystack = b"needle\nxneedle\nneedle";
        let exact = plan
            .span_sum(haystack, ReduceLimits::default())
            .unwrap()
            .accounting
            .upper_bounds;
        let cases = [
            ReduceLimits {
                max_input_bytes: exact.input_bytes - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_source_reads: exact.source_reads - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_work: exact.work - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_candidate_scan_bytes: exact.candidate_scan_bytes - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_literal_comparisons: exact.literal_comparisons - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_assertion_checks: exact.assertion_checks - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_boundary_reads: exact.boundary_reads - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_candidate_events: exact.candidate_events - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_match_events: exact.match_events - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_count: exact.count - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_span_sum: exact.span_sum - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_persistent_bytes: exact.persistent_bytes - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_peak_bytes: exact.peak_bytes - 1,
                ..ReduceLimits::default()
            },
        ];
        for limits in cases {
            assert!(plan.span_sum(haystack, limits).is_err());
        }
    }
}
