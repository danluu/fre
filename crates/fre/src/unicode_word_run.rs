use regex_syntax::{
    ParserBuilder,
    hir::{Class, Hir, HirKind, Look},
};

use crate::{Match, SearchLimits, SearchWindow};

pub const UNICODE_PLAN_ID: &str = "unicode-word-run-linear-v1";
pub const ASCII_PLAN_ID: &str = "ascii-word-run-linear-v1";
pub const AGGREGATE_COUNT_OPERATION_ID: &str = "word-run.count.v1";
pub const AGGREGATE_SPAN_SUM_OPERATION_ID: &str = "word-run.span-sum.v1";

const FIXED_BUILD_WORK: usize = 1;
const FIXED_REDUCE_WORK: usize = 8;
const UNIT_WORK: usize = 4;
const RUN_WORK: usize = 2;
const MATCH_WORK: usize = 4;
// regex-syntax 0.8.11 is exact-pinned and lowers Unicode 16.0's Perl word
// property to this many canonical maximal ranges.
const UNICODE_WORD_RANGE_COUNT: usize = 796;
const ASCII_WORD_RANGES: [(u8, u8); 4] = [(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WordMode {
    Ascii,
    Unicode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    minimum_scalars: usize,
    mode: WordMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accounting {
    pub(crate) work: u64,
    pub(crate) bytes_examined: usize,
    pub(crate) scalars_decoded: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each boolean is an independently authenticated regex semantic, not mutable state"
)]
pub struct AggregateOperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub minimum_scalars: usize,
    pub unicode: bool,
    pub greedy: bool,
    pub complete_word_boundaries: bool,
    pub invalid_bytes_are_non_word: bool,
    pub non_overlapping: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateBuildLimits {
    pub max_build_work: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl AggregateBuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_build_work: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for AggregateBuildLimits {
    fn default() -> Self {
        Self {
            max_build_work: 4_096,
            max_scratch_bytes: 0,
            max_persistent_bytes: 4_096,
            max_peak_bytes: 4_096,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateBuildAccounting {
    pub work_upper_bound: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateReduceLimits {
    pub max_input_bytes: usize,
    pub max_source_reads: usize,
    pub max_work: usize,
    pub max_unit_events: usize,
    pub max_run_events: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl AggregateReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_input_bytes: usize::MAX,
            max_source_reads: usize::MAX,
            max_work: usize::MAX,
            max_unit_events: usize::MAX,
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

impl Default for AggregateReduceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 512 * 1024 * 1024,
            max_source_reads: 512 * 1024 * 1024,
            max_work: 16 * 1024 * 1024 * 1024,
            max_unit_events: 512 * 1024 * 1024,
            max_run_events: 512 * 1024 * 1024,
            max_match_events: 512 * 1024 * 1024,
            max_count: 512 * 1024 * 1024,
            max_span_sum: u64::MAX,
            max_scratch_bytes: 0,
            max_persistent_bytes: 4_096,
            max_peak_bytes: 4_096,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateReduceUpperBounds {
    pub input_bytes: usize,
    pub source_reads: usize,
    pub work: usize,
    pub unit_events: usize,
    pub run_events: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateReduceActual {
    pub source_reads: usize,
    pub work: usize,
    pub units: usize,
    pub runs: usize,
    pub matches: usize,
    pub count: u64,
    pub span_sum: u64,
    pub scratch_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateReduceAccounting {
    pub identity: AggregateOperationIdentity,
    pub upper_bounds: AggregateReduceUpperBounds,
    pub actual: AggregateReduceActual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateCountResult {
    pub count: u64,
    pub accounting: AggregateReduceAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateSpanSumResult {
    pub span_sum: u64,
    pub accounting: AggregateReduceAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AggregateBuildError {
    WorkLimit { needed: usize, limit: usize },
    ScratchLimit { needed: usize, limit: usize },
    PersistentLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
}

impl core::fmt::Display for AggregateBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "word-run aggregate build failed: {self:?}")
    }
}

impl std::error::Error for AggregateBuildError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateReduceResource {
    SourceReads,
    Work,
    UnitEvents,
    RunEvents,
    MatchEvents,
    Count,
    SpanSum,
    ScratchBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AggregateReduceError {
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
    UnitEventsLimit {
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
        resource: AggregateReduceResource,
        actual: u64,
        upper: u64,
    },
}

impl core::fmt::Display for AggregateReduceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "word-run aggregate reduction failed: {self:?}")
    }
}

impl std::error::Error for AggregateReduceError {}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AggregateInspection {
    pub(crate) plan: Plan,
    pub(crate) work: usize,
    pub(crate) hir_nodes: usize,
    pub(crate) captures: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum AggregateInspectionOutcome {
    Eligible(AggregateInspection),
    Ineligible { work: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AggregateInspectionError {
    WorkLimit { needed: usize, limit: usize },
    Overflow,
}

impl Accounting {
    #[must_use]
    pub const fn work(self) -> u64 {
        self.work
    }

    #[must_use]
    pub const fn bytes_examined(self) -> usize {
        self.bytes_examined
    }

    #[must_use]
    pub const fn scalars_decoded(self) -> usize {
        self.scalars_decoded
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    WorkLimitExceeded {
        needed: u64,
        limit: u64,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                f,
                "word-run window {start}..{end} exceeds haystack length {haystack_len}"
            ),
            Self::WorkLimitExceeded { needed, limit } => write!(
                f,
                "word-run search needs {needed} work units, exceeding {limit}"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl Plan {
    const fn new(minimum_scalars: usize, mode: WordMode) -> Self {
        Self {
            minimum_scalars,
            mode,
        }
    }

    pub(crate) const fn plan_id(self) -> &'static str {
        match self.mode {
            WordMode::Ascii => ASCII_PLAN_ID,
            WordMode::Unicode => UNICODE_PLAN_ID,
        }
    }

    pub(crate) fn aggregate_build_accounting(
        self,
        limits: AggregateBuildLimits,
    ) -> Result<AggregateBuildAccounting, AggregateBuildError> {
        let accounting = AggregateBuildAccounting {
            work_upper_bound: FIXED_BUILD_WORK,
            scratch_bytes: 0,
            persistent_bytes: core::mem::size_of_val(&self),
            peak_bytes: core::mem::size_of_val(&self),
        };
        enforce_build(
            accounting.work_upper_bound,
            limits.max_build_work,
            AggregateBuildResource::Work,
        )?;
        enforce_build(
            accounting.scratch_bytes,
            limits.max_scratch_bytes,
            AggregateBuildResource::Scratch,
        )?;
        enforce_build(
            accounting.persistent_bytes,
            limits.max_persistent_bytes,
            AggregateBuildResource::Persistent,
        )?;
        enforce_build(
            accounting.peak_bytes,
            limits.max_peak_bytes,
            AggregateBuildResource::Peak,
        )?;
        Ok(accounting)
    }

    pub(crate) const fn aggregate_count_identity(self) -> AggregateOperationIdentity {
        self.aggregate_identity(AGGREGATE_COUNT_OPERATION_ID)
    }

    pub(crate) const fn aggregate_span_sum_identity(self) -> AggregateOperationIdentity {
        self.aggregate_identity(AGGREGATE_SPAN_SUM_OPERATION_ID)
    }

    const fn aggregate_identity(self, operation_id: &'static str) -> AggregateOperationIdentity {
        AggregateOperationIdentity {
            plan_id: self.plan_id(),
            operation_id,
            minimum_scalars: self.minimum_scalars,
            unicode: matches!(self.mode, WordMode::Unicode),
            greedy: true,
            complete_word_boundaries: true,
            invalid_bytes_are_non_word: true,
            non_overlapping: true,
        }
    }

    pub(crate) fn aggregate_count(
        self,
        haystack: &[u8],
        limits: AggregateReduceLimits,
    ) -> Result<AggregateCountResult, AggregateReduceError> {
        let upper = self.aggregate_preflight(haystack.len(), AggregateOperation::Count, limits)?;
        let actual = self.aggregate_scan(haystack, AggregateOperation::Count, upper)?;
        Ok(AggregateCountResult {
            count: actual.count,
            accounting: AggregateReduceAccounting {
                identity: self.aggregate_count_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }

    pub(crate) fn aggregate_span_sum(
        self,
        haystack: &[u8],
        limits: AggregateReduceLimits,
    ) -> Result<AggregateSpanSumResult, AggregateReduceError> {
        let upper =
            self.aggregate_preflight(haystack.len(), AggregateOperation::SpanSum, limits)?;
        let actual = self.aggregate_scan(haystack, AggregateOperation::SpanSum, upper)?;
        Ok(AggregateSpanSumResult {
            span_sum: actual.span_sum,
            accounting: AggregateReduceAccounting {
                identity: self.aggregate_span_sum_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }

    fn aggregate_preflight(
        self,
        input_bytes: usize,
        operation: AggregateOperation,
        limits: AggregateReduceLimits,
    ) -> Result<AggregateReduceUpperBounds, AggregateReduceError> {
        let upper = self.aggregate_upper_bounds(input_bytes, operation)?;
        enforce_reduce(upper, limits)?;
        Ok(upper)
    }

    fn aggregate_upper_bounds(
        self,
        input_bytes: usize,
        operation: AggregateOperation,
    ) -> Result<AggregateReduceUpperBounds, AggregateReduceError> {
        let unit_events = input_bytes;
        let run_events = input_bytes;
        let match_events = input_bytes.checked_div(self.minimum_scalars).ok_or(
            AggregateReduceError::ArithmeticOverflow {
                computation: "input bytes divided by minimum word scalars",
            },
        )?;
        let count =
            u64::try_from(match_events).map_err(|_| AggregateReduceError::ArithmeticOverflow {
                computation: "match-event bound as u64",
            })?;
        let span_sum = match operation {
            AggregateOperation::Count => 0,
            AggregateOperation::SpanSum => u64::try_from(input_bytes).map_err(|_| {
                AggregateReduceError::ArithmeticOverflow {
                    computation: "input length as span-sum bound",
                }
            })?,
        };
        let work = input_bytes
            .checked_mul(UNIT_WORK)
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
            .ok_or(AggregateReduceError::ArithmeticOverflow {
                computation: "complete reduction work bound",
            })?;
        let persistent_bytes = core::mem::size_of::<Self>();
        Ok(AggregateReduceUpperBounds {
            input_bytes,
            source_reads: input_bytes,
            work,
            unit_events,
            run_events,
            match_events,
            count,
            span_sum,
            scratch_bytes: 0,
            persistent_bytes,
            peak_bytes: persistent_bytes,
        })
    }

    fn aggregate_scan(
        self,
        haystack: &[u8],
        operation: AggregateOperation,
        upper: AggregateReduceUpperBounds,
    ) -> Result<AggregateReduceActual, AggregateReduceError> {
        let mut actual = AggregateReduceActual {
            source_reads: 0,
            work: FIXED_REDUCE_WORK,
            units: 0,
            runs: 0,
            matches: 0,
            count: 0,
            span_sum: 0,
            scratch_bytes: 0,
        };
        let mut position = 0_usize;
        let mut run_start = 0_usize;
        let mut run_scalars = 0_usize;
        while position < haystack.len() {
            let (word, width) = match self.mode {
                WordMode::Ascii => (is_ascii_word(haystack[position]), 1),
                WordMode::Unicode => decode_first(&haystack[position..])
                    .map_or((false, 1), |(scalar, width)| {
                        (is_unicode_word(scalar), width)
                    }),
            };
            actual.source_reads = checked_add(actual.source_reads, width, "actual source reads")?;
            actual.units = checked_add(actual.units, 1, "actual decoded units")?;
            actual.work = checked_add(actual.work, UNIT_WORK, "actual unit work")?;
            if word {
                if run_scalars == 0 {
                    run_start = position;
                }
                run_scalars = checked_add(run_scalars, 1, "actual word-run scalar length")?;
            } else if run_scalars != 0 {
                self.aggregate_finish_run(
                    run_start,
                    position,
                    run_scalars,
                    operation,
                    &mut actual,
                )?;
                run_scalars = 0;
            }
            position = checked_add(position, width, "actual input cursor")?;
        }
        if run_scalars != 0 {
            self.aggregate_finish_run(
                run_start,
                haystack.len(),
                run_scalars,
                operation,
                &mut actual,
            )?;
        }
        verify_aggregate_actual(actual, upper)?;
        Ok(actual)
    }

    fn aggregate_finish_run(
        self,
        start: usize,
        end: usize,
        scalars: usize,
        operation: AggregateOperation,
        actual: &mut AggregateReduceActual,
    ) -> Result<(), AggregateReduceError> {
        actual.runs = checked_add(actual.runs, 1, "actual word-run events")?;
        actual.work = checked_add(actual.work, RUN_WORK, "actual word-run work")?;
        if scalars < self.minimum_scalars {
            return Ok(());
        }
        actual.matches = checked_add(actual.matches, 1, "actual match events")?;
        actual.count =
            actual
                .count
                .checked_add(1)
                .ok_or(AggregateReduceError::ArithmeticOverflow {
                    computation: "actual match count",
                })?;
        actual.work = checked_add(actual.work, MATCH_WORK, "actual match work")?;
        if operation == AggregateOperation::SpanSum {
            let width = end
                .checked_sub(start)
                .ok_or(AggregateReduceError::ArithmeticOverflow {
                    computation: "actual match width",
                })?;
            actual.span_sum = actual
                .span_sum
                .checked_add(u64::try_from(width).map_err(|_| {
                    AggregateReduceError::ArithmeticOverflow {
                        computation: "actual match width as u64",
                    }
                })?)
                .ok_or(AggregateReduceError::ArithmeticOverflow {
                    computation: "actual span sum",
                })?;
        }
        Ok(())
    }

    pub(crate) fn find_window(
        self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(Error::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        match self.mode {
            WordMode::Ascii => self.find_ascii_window(haystack, window, limits),
            WordMode::Unicode => self.find_unicode_window(haystack, window, limits),
        }
    }

    fn find_ascii_window(
        self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        let mut accounting = Accounting {
            work: 0,
            bytes_examined: 0,
            scalars_decoded: 0,
        };
        let mut position = window.start();
        while position < window.end() {
            charge(&mut accounting, limits)?;
            let byte = haystack[position];
            accounting.bytes_examined = accounting.bytes_examined.saturating_add(1);
            accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
            if !is_ascii_word(byte)
                || position
                    .checked_sub(1)
                    .is_some_and(|before| is_ascii_word(haystack[before]))
            {
                position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
                continue;
            }

            let start = position;
            position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                needed: u64::MAX,
                limit: limits.max_work,
            })?;
            while position < window.end() && is_ascii_word(haystack[position]) {
                charge(&mut accounting, limits)?;
                accounting.bytes_examined = accounting.bytes_examined.saturating_add(1);
                accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
                position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
            }
            if position.saturating_sub(start) >= self.minimum_scalars
                && !haystack
                    .get(position)
                    .is_some_and(|&byte| is_ascii_word(byte))
            {
                return Ok((
                    Some(Match {
                        start,
                        end: position,
                    }),
                    accounting,
                ));
            }
        }
        Ok((None, accounting))
    }

    fn find_unicode_window(
        self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        let mut accounting = Accounting {
            work: 0,
            bytes_examined: 0,
            scalars_decoded: 0,
        };
        let mut position = window.start();
        while position < window.end() {
            charge(&mut accounting, limits)?;
            let Some((scalar, width)) = decode_first(&haystack[position..window.end()]) else {
                position = position.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
                accounting.bytes_examined = accounting.bytes_examined.saturating_add(1);
                continue;
            };
            accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
            accounting.bytes_examined = accounting.bytes_examined.saturating_add(width);
            if !is_unicode_word(scalar) || unicode_word_before(haystack, position) {
                position = position
                    .checked_add(width)
                    .ok_or(Error::WorkLimitExceeded {
                        needed: u64::MAX,
                        limit: limits.max_work,
                    })?;
                continue;
            }

            let start = position;
            let mut count = 1_usize;
            position = position
                .checked_add(width)
                .ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
            while position < window.end() {
                charge(&mut accounting, limits)?;
                let Some((next, next_width)) = decode_first(&haystack[position..window.end()])
                else {
                    break;
                };
                accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
                accounting.bytes_examined = accounting.bytes_examined.saturating_add(next_width);
                if !is_unicode_word(next) {
                    break;
                }
                count = count.saturating_add(1);
                position = position
                    .checked_add(next_width)
                    .ok_or(Error::WorkLimitExceeded {
                        needed: u64::MAX,
                        limit: limits.max_work,
                    })?;
            }
            if count >= self.minimum_scalars && !unicode_word_after(haystack, position) {
                return Ok((
                    Some(Match {
                        start,
                        end: position,
                    }),
                    accounting,
                ));
            }
        }
        Ok((None, accounting))
    }
}

pub(crate) fn extract(hir: &Hir) -> Option<Plan> {
    let HirKind::Concat(parts) = transparent(hir).kind() else {
        return None;
    };
    let [start, repeated, end] = parts.as_slice() else {
        return None;
    };
    let mode = match (transparent(start).kind(), transparent(end).kind()) {
        (HirKind::Look(Look::WordAscii), HirKind::Look(Look::WordAscii)) => WordMode::Ascii,
        (HirKind::Look(Look::WordUnicode), HirKind::Look(Look::WordUnicode)) => WordMode::Unicode,
        _ => return None,
    };
    let HirKind::Repetition(repetition) = transparent(repeated).kind() else {
        return None;
    };
    if repetition.min == 0 || repetition.max.is_some() || !repetition.greedy {
        return None;
    }
    match (mode, transparent(&repetition.sub).kind()) {
        (WordMode::Ascii, HirKind::Class(Class::Bytes(class)))
            if class == &parse_ascii_word_class()? => {}
        (WordMode::Unicode, HirKind::Class(Class::Unicode(class)))
            if class == &parse_unicode_word_class()? => {}
        _ => return None,
    }
    Some(Plan::new(usize::try_from(repetition.min).ok()?, mode))
}

pub(crate) fn inspect_aggregate(
    hir: &Hir,
    limit: usize,
) -> Result<AggregateInspectionOutcome, AggregateInspectionError> {
    let mut accounting = InspectionAccounting::default();
    let root = peel_captures_accounted(hir, limit, &mut accounting)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(accounting.ineligible());
    };
    accounting.charge(parts.len(), limit)?;
    let [start, repeated, end] = parts.as_slice() else {
        return Ok(accounting.ineligible());
    };
    let start = peel_captures_accounted(start, limit, &mut accounting)?;
    let end = peel_captures_accounted(end, limit, &mut accounting)?;
    let mode = match (start.kind(), end.kind()) {
        (HirKind::Look(Look::WordAscii), HirKind::Look(Look::WordAscii)) => WordMode::Ascii,
        (HirKind::Look(Look::WordUnicode), HirKind::Look(Look::WordUnicode)) => WordMode::Unicode,
        _ => return Ok(accounting.ineligible()),
    };
    let repeated = peel_captures_accounted(repeated, limit, &mut accounting)?;
    let HirKind::Repetition(repetition) = repeated.kind() else {
        return Ok(accounting.ineligible());
    };
    accounting.charge(3, limit)?;
    if repetition.min == 0 || repetition.max.is_some() || !repetition.greedy {
        return Ok(accounting.ineligible());
    }
    let class = peel_captures_accounted(&repetition.sub, limit, &mut accounting)?;
    match (mode, class.kind()) {
        (WordMode::Ascii, HirKind::Class(Class::Bytes(class))) => {
            accounting.charge(class.ranges().len(), limit)?;
            if !is_exact_ascii_word_class(class) {
                return Ok(accounting.ineligible());
            }
        }
        (WordMode::Unicode, HirKind::Class(Class::Unicode(class))) => {
            accounting.charge(class.ranges().len(), limit)?;
            if !is_exact_unicode_word_class(class, limit, &mut accounting)? {
                return Ok(accounting.ineligible());
            }
        }
        _ => return Ok(accounting.ineligible()),
    }
    let minimum_scalars =
        usize::try_from(repetition.min).map_err(|_| AggregateInspectionError::Overflow)?;
    Ok(AggregateInspectionOutcome::Eligible(AggregateInspection {
        plan: Plan::new(minimum_scalars, mode),
        work: accounting.work,
        hir_nodes: accounting.hir_nodes,
        captures: accounting.captures,
    }))
}

#[derive(Default)]
struct InspectionAccounting {
    work: usize,
    hir_nodes: usize,
    captures: usize,
}

impl InspectionAccounting {
    fn charge(&mut self, units: usize, limit: usize) -> Result<(), AggregateInspectionError> {
        let needed = self
            .work
            .checked_add(units)
            .ok_or(AggregateInspectionError::Overflow)?;
        if needed > limit {
            return Err(AggregateInspectionError::WorkLimit { needed, limit });
        }
        self.work = needed;
        Ok(())
    }

    fn visit(&mut self, limit: usize) -> Result<(), AggregateInspectionError> {
        self.charge(1, limit)?;
        self.hir_nodes = self
            .hir_nodes
            .checked_add(1)
            .ok_or(AggregateInspectionError::Overflow)?;
        Ok(())
    }

    const fn ineligible(&self) -> AggregateInspectionOutcome {
        AggregateInspectionOutcome::Ineligible { work: self.work }
    }
}

fn peel_captures_accounted<'a>(
    mut hir: &'a Hir,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<&'a Hir, AggregateInspectionError> {
    loop {
        accounting.visit(limit)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        accounting.captures = accounting
            .captures
            .checked_add(1)
            .ok_or(AggregateInspectionError::Overflow)?;
        hir = &capture.sub;
    }
}

fn is_exact_ascii_word_class(class: &regex_syntax::hir::ClassBytes) -> bool {
    class.ranges().len() == ASCII_WORD_RANGES.len()
        && class
            .ranges()
            .iter()
            .zip(ASCII_WORD_RANGES)
            .all(|(actual, (start, end))| actual.start() == start && actual.end() == end)
}

fn is_exact_unicode_word_class(
    class: &regex_syntax::hir::ClassUnicode,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<bool, AggregateInspectionError> {
    if class.ranges().len() != UNICODE_WORD_RANGE_COUNT {
        return Ok(false);
    }
    for range in class.ranges() {
        if !charged_is_unicode_word(range.start(), limit, accounting)?
            || !charged_is_unicode_word(range.end(), limit, accounting)?
        {
            return Ok(false);
        }
        if let Some(previous) = previous_scalar(range.start())
            && charged_is_unicode_word(previous, limit, accounting)?
        {
            return Ok(false);
        }
        if let Some(next) = next_scalar(range.end())
            && charged_is_unicode_word(next, limit, accounting)?
        {
            return Ok(false);
        }
    }
    // Every admitted range is therefore one complete maximal interval of the
    // pinned word property. Equal cardinality proves that none is merged,
    // split, duplicated or omitted without retaining a second range table.
    Ok(true)
}

fn charged_is_unicode_word(
    scalar: char,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<bool, AggregateInspectionError> {
    accounting.charge(1, limit)?;
    Ok(is_unicode_word(scalar))
}

fn previous_scalar(scalar: char) -> Option<char> {
    let codepoint = u32::from(scalar).checked_sub(1)?;
    if codepoint == 0xDFFF {
        Some('\u{D7FF}')
    } else {
        char::from_u32(codepoint)
    }
}

fn next_scalar(scalar: char) -> Option<char> {
    let codepoint = u32::from(scalar).checked_add(1)?;
    if codepoint == 0xD800 {
        Some('\u{E000}')
    } else {
        char::from_u32(codepoint)
    }
}

fn transparent(mut hir: &Hir) -> &Hir {
    while let HirKind::Capture(capture) = hir.kind() {
        hir = &capture.sub;
    }
    hir
}

fn parse_ascii_word_class() -> Option<regex_syntax::hir::ClassBytes> {
    let hir = ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .build()
        .parse(r"\w")
        .ok()?;
    let HirKind::Class(Class::Bytes(class)) = hir.kind() else {
        return None;
    };
    Some(class.clone())
}

fn parse_unicode_word_class() -> Option<regex_syntax::hir::ClassUnicode> {
    let hir = ParserBuilder::new()
        .unicode(true)
        .utf8(false)
        .build()
        .parse(r"\w")
        .ok()?;
    let HirKind::Class(Class::Unicode(class)) = hir.kind() else {
        return None;
    };
    Some(class.clone())
}

fn charge(accounting: &mut Accounting, limits: SearchLimits) -> Result<(), Error> {
    let needed = accounting.work.saturating_add(1);
    if needed > limits.max_work {
        return Err(Error::WorkLimitExceeded {
            needed,
            limit: limits.max_work,
        });
    }
    accounting.work = needed;
    Ok(())
}

fn unicode_word_before(haystack: &[u8], position: usize) -> bool {
    decode_last(&haystack[..position]).is_some_and(|(scalar, _)| is_unicode_word(scalar))
}

fn unicode_word_after(haystack: &[u8], position: usize) -> bool {
    decode_first(&haystack[position..]).is_some_and(|(scalar, _)| is_unicode_word(scalar))
}

fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn is_unicode_word(scalar: char) -> bool {
    if scalar.is_ascii() {
        return scalar == '_' || scalar.is_ascii_alphanumeric();
    }
    regex_syntax::try_is_word_character(scalar)
        .expect("fre enables regex-syntax's Unicode Perl tables")
}

fn decode_first(bytes: &[u8]) -> Option<(char, usize)> {
    let first = *bytes.first()?;
    if first.is_ascii() {
        return Some((char::from(first), 1));
    }
    let width = match first {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    let scalar = core::str::from_utf8(bytes.get(..width)?)
        .ok()?
        .chars()
        .next()?;
    Some((scalar, width))
}

fn decode_last(bytes: &[u8]) -> Option<(char, usize)> {
    let mut start = bytes.len().checked_sub(1)?;
    let lower = bytes.len().saturating_sub(4);
    while start > lower && matches!(bytes[start], 0x80..=0xBF) {
        start = start.checked_sub(1)?;
    }
    let (scalar, width) = decode_first(&bytes[start..])?;
    (start.checked_add(width) == Some(bytes.len())).then_some((scalar, width))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AggregateOperation {
    Count,
    SpanSum,
}

#[derive(Clone, Copy)]
enum AggregateBuildResource {
    Work,
    Scratch,
    Persistent,
    Peak,
}

fn enforce_build(
    needed: usize,
    limit: usize,
    resource: AggregateBuildResource,
) -> Result<(), AggregateBuildError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        AggregateBuildResource::Work => AggregateBuildError::WorkLimit { needed, limit },
        AggregateBuildResource::Scratch => AggregateBuildError::ScratchLimit { needed, limit },
        AggregateBuildResource::Persistent => {
            AggregateBuildError::PersistentLimit { needed, limit }
        }
        AggregateBuildResource::Peak => AggregateBuildError::PeakLimit { needed, limit },
    })
}

fn enforce_reduce(
    upper: AggregateReduceUpperBounds,
    limits: AggregateReduceLimits,
) -> Result<(), AggregateReduceError> {
    macro_rules! enforce {
        ($needed:expr, $limit:expr, $variant:ident) => {
            if $needed > $limit {
                return Err(AggregateReduceError::$variant {
                    needed: $needed,
                    limit: $limit,
                });
            }
        };
    }
    enforce!(upper.input_bytes, limits.max_input_bytes, InputBytesLimit);
    enforce!(
        upper.source_reads,
        limits.max_source_reads,
        SourceReadsLimit
    );
    enforce!(upper.work, limits.max_work, WorkLimit);
    enforce!(upper.unit_events, limits.max_unit_events, UnitEventsLimit);
    enforce!(upper.run_events, limits.max_run_events, RunEventsLimit);
    enforce!(
        upper.match_events,
        limits.max_match_events,
        MatchEventsLimit
    );
    enforce!(upper.count, limits.max_count, CountLimit);
    enforce!(upper.span_sum, limits.max_span_sum, SpanSumLimit);
    enforce!(upper.scratch_bytes, limits.max_scratch_bytes, ScratchLimit);
    enforce!(
        upper.persistent_bytes,
        limits.max_persistent_bytes,
        PersistentLimit
    );
    enforce!(upper.peak_bytes, limits.max_peak_bytes, PeakLimit);
    Ok(())
}

fn checked_add(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, AggregateReduceError> {
    left.checked_add(right)
        .ok_or(AggregateReduceError::ArithmeticOverflow { computation })
}

fn verify_aggregate_actual(
    actual: AggregateReduceActual,
    upper: AggregateReduceUpperBounds,
) -> Result<(), AggregateReduceError> {
    verify_resource(
        AggregateReduceResource::SourceReads,
        actual.source_reads,
        upper.source_reads,
    )?;
    verify_resource(AggregateReduceResource::Work, actual.work, upper.work)?;
    verify_resource(
        AggregateReduceResource::UnitEvents,
        actual.units,
        upper.unit_events,
    )?;
    verify_resource(
        AggregateReduceResource::RunEvents,
        actual.runs,
        upper.run_events,
    )?;
    verify_resource(
        AggregateReduceResource::MatchEvents,
        actual.matches,
        upper.match_events,
    )?;
    verify_resource(AggregateReduceResource::Count, actual.count, upper.count)?;
    verify_resource(
        AggregateReduceResource::SpanSum,
        actual.span_sum,
        upper.span_sum,
    )?;
    verify_resource(
        AggregateReduceResource::ScratchBytes,
        actual.scratch_bytes,
        upper.scratch_bytes,
    )?;
    Ok(())
}

fn verify_resource<T>(
    resource: AggregateReduceResource,
    actual: T,
    upper: T,
) -> Result<(), AggregateReduceError>
where
    T: Copy + Ord + TryInto<u64>,
{
    if actual <= upper {
        return Ok(());
    }
    Err(AggregateReduceError::AccountingInvariant {
        resource,
        actual: actual.try_into().unwrap_or(u64::MAX),
        upper: upper.try_into().unwrap_or(u64::MAX),
    })
}
