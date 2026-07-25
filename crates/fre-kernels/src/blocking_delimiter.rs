//! Whole-operation reduction for `D [^D]{0,N} T D`.
//!
//! Admission proves that `D` is exactly two byte delimiters, the repeated
//! class is their complete complement, and `T` is disjoint from `D`. The next
//! delimiter therefore uniquely decides whether the current delimiter can
//! start a match: it must be within the bounded distance and its preceding
//! byte must be in `T`. A failed closing delimiter becomes the next opening
//! candidate; a successful closing delimiter is consumed. One monotone
//! `memchr2` stream consequently preserves greedy, leftmost-first,
//! non-overlapping byte semantics without operation allocation.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "resource and index arithmetic is checked; bitmap shifts use proved 0..=63 operands"
)]

use core::{fmt, mem::size_of};

use memchr::memchr2;

use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError};

pub const PLAN_ID: &str = "blocking-delimiter.consecutive-pairs.v1";
pub const COUNT_OPERATION_ID: &str = "blocking-delimiter.count.unicode-off.v1";
pub const SPAN_SUM_OPERATION_ID: &str = "blocking-delimiter.span-sum.unicode-off.v1";

const FIXED_BUILD_WORK: usize = 16;
const TERMINAL_WORD_BUILD_WORK: usize = 2;
const TERMINAL_MEMBER_BUILD_WORK: usize = 1;
const FIXED_REDUCE_WORK: usize = 8;
const SCAN_BYTE_WORK: usize = 1;
const DELIMITER_EVENT_WORK: usize = 2;
const PAIR_EVENT_WORK: usize = 2;
const TERMINAL_READ_WORK: usize = 1;
const MATCH_WORK: usize = 4;
const MINIMUM_MATCH_BYTES: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Topology {
    DelimiterComplementBoundedTerminalDelimiter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the cache identity records independent proved semantic invariants explicitly"
)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub delimiters: [u8; 2],
    pub terminal_words: [u64; 4],
    pub maximum_middle_bytes: usize,
    pub topology: Topology,
    pub unicode: bool,
    pub greedy: bool,
    pub blocking_delimiter: bool,
    pub non_overlapping: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_delimiter_members: usize,
    pub max_terminal_members: usize,
    pub max_middle_bytes: usize,
    pub max_build_work: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl BuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_delimiter_members: usize::MAX,
            max_terminal_members: usize::MAX,
            max_middle_bytes: usize::MAX,
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
            max_delimiter_members: 2,
            max_terminal_members: 256,
            max_middle_bytes: 1 << 20,
            max_build_work: 1 << 20,
            max_scratch_bytes: 0,
            max_persistent_bytes: 1 << 20,
            max_peak_bytes: 1 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub delimiter_members: usize,
    pub terminal_members: usize,
    pub maximum_middle_bytes: usize,
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
    pub max_delimiter_scan_bytes: usize,
    pub max_delimiter_events: usize,
    pub max_pair_events: usize,
    pub max_terminal_reads: usize,
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
            max_delimiter_scan_bytes: usize::MAX,
            max_delimiter_events: usize::MAX,
            max_pair_events: usize::MAX,
            max_terminal_reads: usize::MAX,
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
            max_source_reads: 1024 * 1024 * 1024,
            max_work: 8 * 1024 * 1024 * 1024,
            max_delimiter_scan_bytes: 512 * 1024 * 1024,
            max_delimiter_events: 512 * 1024 * 1024,
            max_pair_events: 512 * 1024 * 1024,
            max_terminal_reads: 512 * 1024 * 1024,
            max_match_events: 64 * 1024 * 1024,
            max_count: 64 * 1024 * 1024,
            max_span_sum: u64::MAX,
            max_scratch_bytes: 0,
            max_persistent_bytes: 1 << 20,
            max_peak_bytes: 1 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub input_bytes: usize,
    pub source_reads: usize,
    pub work: usize,
    pub delimiter_scan_bytes: usize,
    pub delimiter_events: usize,
    pub pair_events: usize,
    pub terminal_reads: usize,
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
    pub work: usize,
    pub delimiter_scan_bytes: usize,
    pub delimiters: usize,
    pub pairs: usize,
    pub terminal_reads: usize,
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
    NonCanonicalDelimiters,
    EmptyTerminalClass,
    TerminalContainsDelimiter { delimiter: u8 },
    DelimiterMembersLimit { needed: usize, limit: usize },
    TerminalMembersLimit { needed: usize, limit: usize },
    MiddleBytesLimit { needed: usize, limit: usize },
    WorkLimit { needed: usize, limit: usize },
    ScratchLimit { needed: usize, limit: usize },
    PersistentLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "blocking-delimiter construction failed: {self:?}"
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
    DelimiterScanBytesLimit {
        needed: usize,
        limit: usize,
    },
    DelimiterEventsLimit {
        needed: usize,
        limit: usize,
    },
    PairEventsLimit {
        needed: usize,
        limit: usize,
    },
    TerminalReadsLimit {
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
        write!(formatter, "blocking-delimiter reduction failed: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

#[derive(Debug)]
pub struct BlockingDelimiterPlan {
    delimiters: [u8; 2],
    terminal_words: [u64; 4],
    maximum_middle_bytes: usize,
    build: BuildAccounting,
}

impl BlockingDelimiterPlan {
    pub fn build(
        delimiters: [u8; 2],
        terminal_words: [u64; 4],
        maximum_middle_bytes: usize,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_attempt(delimiters, terminal_words, maximum_middle_bytes, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build while retaining exact successful or partial terminal effects.
    #[allow(
        clippy::too_many_lines,
        reason = "construction keeps validation, exact accounting, and publication in one auditable transaction"
    )]
    pub fn build_attempt(
        delimiters: [u8; 2],
        terminal_words: [u64; 4],
        maximum_middle_bytes: usize,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>> {
        let mut actual = DirectBuildAttemptActual::default();
        let result = (|| {
            if delimiters[0] >= delimiters[1] {
                return Err(BuildError::NonCanonicalDelimiters);
            }
            let delimiter_members = 2;
            enforce_build(
                delimiter_members,
                limits.max_delimiter_members,
                BuildResource::DelimiterMembers,
            )?;
            let terminal_members = terminal_words.iter().try_fold(0_usize, |total, word| {
                let members = usize::try_from(word.count_ones()).map_err(|_| {
                    BuildError::ArithmeticOverflow {
                        computation: "terminal member word count",
                    }
                })?;
                let charged = members
                    .checked_mul(TERMINAL_MEMBER_BUILD_WORK)
                    .and_then(|work| work.checked_add(TERMINAL_WORD_BUILD_WORK))
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "terminal word build work",
                    })?;
                actual.work = actual
                    .work
                    .checked_add(u64::try_from(charged).map_err(|_| {
                        BuildError::ArithmeticOverflow {
                            computation: "terminal word build work conversion",
                        }
                    })?)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "terminal word build work",
                    })?;
                total
                    .checked_add(members)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "terminal member count",
                    })
            })?;
            if terminal_members == 0 {
                return Err(BuildError::EmptyTerminalClass);
            }
            enforce_build(
                terminal_members,
                limits.max_terminal_members,
                BuildResource::TerminalMembers,
            )?;
            enforce_build(
                maximum_middle_bytes,
                limits.max_middle_bytes,
                BuildResource::MiddleBytes,
            )?;
            for delimiter in delimiters {
                if class_contains(terminal_words, delimiter) {
                    return Err(BuildError::TerminalContainsDelimiter { delimiter });
                }
            }
            maximum_middle_bytes
                .checked_add(2)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "maximum closing-delimiter distance",
                })?;
            let work_upper_bound = terminal_words
                .len()
                .checked_mul(TERMINAL_WORD_BUILD_WORK)
                .and_then(|work| {
                    terminal_members
                        .checked_mul(TERMINAL_MEMBER_BUILD_WORK)
                        .and_then(|members| work.checked_add(members))
                })
                .and_then(|work| work.checked_add(FIXED_BUILD_WORK))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "complete build work",
                })?;
            enforce_build(work_upper_bound, limits.max_build_work, BuildResource::Work)?;
            let scratch_bytes = 0;
            let persistent_bytes = size_of::<Self>();
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
            actual.work = actual
                .work
                .checked_add(u64::try_from(FIXED_BUILD_WORK).map_err(|_| {
                    BuildError::ArithmeticOverflow {
                        computation: "fixed build work conversion",
                    }
                })?)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "complete build work",
                })?;
            debug_assert_eq!(usize::try_from(actual.work), Ok(work_upper_bound));
            actual.copied_bytes = size_of::<[u8; 2]>() + size_of::<[u64; 4]>();
            actual.initialized_bytes = persistent_bytes;
            actual.live_persistent_bytes = persistent_bytes;
            actual.peak_bytes = persistent_bytes;
            Ok(Self {
                delimiters,
                terminal_words,
                maximum_middle_bytes,
                build: BuildAccounting {
                    delimiter_members,
                    terminal_members,
                    maximum_middle_bytes,
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
            delimiters: self.delimiters,
            terminal_words: self.terminal_words,
            maximum_middle_bytes: self.maximum_middle_bytes,
            topology: Topology::DelimiterComplementBoundedTerminalDelimiter,
            unicode: false,
            greedy: true,
            blocking_delimiter: true,
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
        let delimiter_scan_bytes = input_bytes;
        let delimiter_events = input_bytes;
        let pair_events = input_bytes.saturating_sub(1);
        let terminal_reads = pair_events;
        let source_reads = delimiter_scan_bytes.checked_add(terminal_reads).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "complete source reads",
            },
        )?;
        let match_events = input_bytes.checked_div(MINIMUM_MATCH_BYTES).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "match-event bound divisor",
            },
        )?;
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
        let work = delimiter_scan_bytes
            .checked_mul(SCAN_BYTE_WORK)
            .and_then(|value| {
                delimiter_events
                    .checked_mul(DELIMITER_EVENT_WORK)
                    .and_then(|events| value.checked_add(events))
            })
            .and_then(|value| {
                pair_events
                    .checked_mul(PAIR_EVENT_WORK)
                    .and_then(|events| value.checked_add(events))
            })
            .and_then(|value| {
                terminal_reads
                    .checked_mul(TERMINAL_READ_WORK)
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
            source_reads,
            work,
            delimiter_scan_bytes,
            delimiter_events,
            pair_events,
            terminal_reads,
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
            work: FIXED_REDUCE_WORK,
            delimiter_scan_bytes: 0,
            delimiters: 0,
            pairs: 0,
            terminal_reads: 0,
            matches: 0,
            count: 0,
            span_sum: 0,
            scratch_bytes: 0,
        };
        let maximum_distance =
            self.maximum_middle_bytes
                .checked_add(2)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "maximum closing-delimiter distance",
                })?;
        let mut opener = None;
        let mut cursor = 0_usize;
        while cursor < haystack.len() {
            let search = haystack
                .get(cursor..)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "delimiter search window",
                })?;
            let Some(relative) = memchr2(self.delimiters[0], self.delimiters[1], search) else {
                charge_scan(&mut actual, search.len())?;
                break;
            };
            let scanned = relative
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "delimiter scan progress",
                })?;
            charge_scan(&mut actual, scanned)?;
            let delimiter =
                cursor
                    .checked_add(relative)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "absolute delimiter offset",
                    })?;
            charge_delimiter(&mut actual)?;
            cursor = delimiter
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "post-delimiter cursor",
                })?;
            let Some(start) = opener else {
                opener = Some(delimiter);
                continue;
            };
            charge_pair(&mut actual)?;
            let distance = delimiter
                .checked_sub(start)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "delimiter pair distance",
                })?;
            if (2..=maximum_distance).contains(&distance) {
                let terminal_offset =
                    delimiter
                        .checked_sub(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "terminal byte offset",
                        })?;
                let terminal =
                    *haystack
                        .get(terminal_offset)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "terminal byte source position",
                        })?;
                charge_terminal_read(&mut actual)?;
                if class_contains(self.terminal_words, terminal) {
                    record_match(&mut actual, operation, start, delimiter)?;
                    opener = None;
                    continue;
                }
            }
            opener = Some(delimiter);
        }
        actual.source_reads = actual
            .delimiter_scan_bytes
            .checked_add(actual.terminal_reads)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual source reads",
            })?;
        verify_actual(actual, upper)?;
        Ok(actual)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Count,
    SpanSum,
}

fn class_contains(words: [u64; 4], byte: u8) -> bool {
    let word = usize::from(byte >> 6);
    let bit = u32::from(byte & 63);
    words
        .get(word)
        .is_some_and(|bits| bits & (1_u64 << bit) != 0)
}

fn charge_scan(actual: &mut ReduceActualCounters, scanned: usize) -> Result<(), ReduceError> {
    actual.delimiter_scan_bytes =
        checked_add(actual.delimiter_scan_bytes, scanned, "delimiter scan bytes")?;
    let work = scanned
        .checked_mul(SCAN_BYTE_WORK)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "delimiter scan work",
        })?;
    actual.work = checked_add(actual.work, work, "delimiter scan work")?;
    Ok(())
}

fn charge_delimiter(actual: &mut ReduceActualCounters) -> Result<(), ReduceError> {
    actual.delimiters = checked_add(actual.delimiters, 1, "delimiter events")?;
    actual.work = checked_add(actual.work, DELIMITER_EVENT_WORK, "delimiter event work")?;
    Ok(())
}

fn charge_pair(actual: &mut ReduceActualCounters) -> Result<(), ReduceError> {
    actual.pairs = checked_add(actual.pairs, 1, "pair events")?;
    actual.work = checked_add(actual.work, PAIR_EVENT_WORK, "pair event work")?;
    Ok(())
}

fn charge_terminal_read(actual: &mut ReduceActualCounters) -> Result<(), ReduceError> {
    actual.terminal_reads = checked_add(actual.terminal_reads, 1, "terminal reads")?;
    actual.work = checked_add(actual.work, TERMINAL_READ_WORK, "terminal read work")?;
    Ok(())
}

fn record_match(
    actual: &mut ReduceActualCounters,
    operation: Operation,
    start: usize,
    closing_delimiter: usize,
) -> Result<(), ReduceError> {
    actual.matches = checked_add(actual.matches, 1, "match events")?;
    actual.count = actual
        .count
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "actual count",
        })?;
    if operation == Operation::SpanSum {
        let width = closing_delimiter
            .checked_sub(start)
            .and_then(|distance| distance.checked_add(1))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "matched span width",
            })?;
        actual.span_sum = actual
            .span_sum
            .checked_add(
                u64::try_from(width).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "matched span width as u64",
                })?,
            )
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual span sum",
            })?;
    }
    actual.work = checked_add(actual.work, MATCH_WORK, "match work")?;
    Ok(())
}

fn checked_add(left: usize, right: usize, computation: &'static str) -> Result<usize, ReduceError> {
    left.checked_add(right)
        .ok_or(ReduceError::ArithmeticOverflow { computation })
}

fn verify_actual(
    actual: ReduceActualCounters,
    upper: ReduceUpperBounds,
) -> Result<(), ReduceError> {
    verify("source reads", actual.source_reads, upper.source_reads)?;
    verify("work", actual.work, upper.work)?;
    verify(
        "delimiter scan bytes",
        actual.delimiter_scan_bytes,
        upper.delimiter_scan_bytes,
    )?;
    verify("delimiters", actual.delimiters, upper.delimiter_events)?;
    verify("pairs", actual.pairs, upper.pair_events)?;
    verify(
        "terminal reads",
        actual.terminal_reads,
        upper.terminal_reads,
    )?;
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

#[derive(Clone, Copy)]
enum BuildResource {
    DelimiterMembers,
    TerminalMembers,
    MiddleBytes,
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
        BuildResource::DelimiterMembers => BuildError::DelimiterMembersLimit { needed, limit },
        BuildResource::TerminalMembers => BuildError::TerminalMembersLimit { needed, limit },
        BuildResource::MiddleBytes => BuildError::MiddleBytesLimit { needed, limit },
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
    DelimiterScanBytes,
    DelimiterEvents,
    PairEvents,
    TerminalReads,
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
            upper.delimiter_scan_bytes,
            limits.max_delimiter_scan_bytes,
            ReduceResource::DelimiterScanBytes,
        ),
        (
            upper.delimiter_events,
            limits.max_delimiter_events,
            ReduceResource::DelimiterEvents,
        ),
        (
            upper.pair_events,
            limits.max_pair_events,
            ReduceResource::PairEvents,
        ),
        (
            upper.terminal_reads,
            limits.max_terminal_reads,
            ReduceResource::TerminalReads,
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
        ReduceResource::DelimiterScanBytes => {
            ReduceError::DelimiterScanBytesLimit { needed, limit }
        }
        ReduceResource::DelimiterEvents => ReduceError::DelimiterEventsLimit { needed, limit },
        ReduceResource::PairEvents => ReduceError::PairEventsLimit { needed, limit },
        ReduceResource::TerminalReads => ReduceError::TerminalReadsLimit { needed, limit },
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

    const DELIMITERS: [u8; 2] = [b'"', b'\''];

    fn words(bytes: &[u8]) -> [u64; 4] {
        let mut words = [0_u64; 4];
        for &byte in bytes {
            let word = usize::from(byte >> 6);
            let bit = u32::from(byte & 63);
            words[word] |= 1_u64 << bit;
        }
        words
    }

    fn plan(maximum_middle_bytes: usize) -> BlockingDelimiterPlan {
        BlockingDelimiterPlan::build(
            DELIMITERS,
            words(b"?!."),
            maximum_middle_bytes,
            BuildLimits::default(),
        )
        .unwrap()
    }

    fn oracle(maximum_middle_bytes: usize, haystack: &[u8]) -> (u64, u64) {
        let pattern = format!(r#"["'][^"']{{0,{maximum_middle_bytes}}}[?!.]["']"#);
        RegexBuilder::new(&pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .fold((0_u64, 0_u64), |sum, matched| {
                (
                    sum.0.checked_add(1).unwrap(),
                    sum.1
                        .checked_add(u64::try_from(matched.len()).unwrap())
                        .unwrap(),
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
    fn consecutive_delimiters_preserve_blocking_restart_and_nonoverlap() {
        let plan = plan(3);
        for haystack in [
            b"\"?\"".as_slice(),
            b"\"x?\"".as_slice(),
            b"\"bad'\"?\"".as_slice(),
            b"\"?\"?\"".as_slice(),
            b"'x!'\"y.\"".as_slice(),
            b"\"x\xff?\"".as_slice(),
        ] {
            let expected = oracle(3, haystack);
            assert_eq!(
                plan.count(haystack, ReduceLimits::default()).unwrap().count,
                expected.0,
                "haystack={haystack:?}"
            );
            assert_eq!(
                plan.span_sum(haystack, ReduceLimits::default())
                    .unwrap()
                    .span_sum,
                expected.1,
                "haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn exhaustive_small_byte_semantics_match_pinned_regex() {
        let plan = plan(2);
        for haystack in generate(&[b'"', b'\'', b'?', b'.', b'x', 0xFF], 5) {
            let expected = oracle(2, &haystack);
            assert_eq!(
                plan.count(&haystack, ReduceLimits::default())
                    .unwrap()
                    .count,
                expected.0,
                "haystack={haystack:?}"
            );
            assert_eq!(
                plan.span_sum(&haystack, ReduceLimits::default())
                    .unwrap()
                    .span_sum,
                expected.1,
                "haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn identity_and_construction_refusals_are_exact() {
        let plan = plan(30);
        let identity = plan.span_sum_identity();
        assert_eq!(identity.delimiters, DELIMITERS);
        assert_eq!(identity.maximum_middle_bytes, 30);
        assert_eq!(
            identity.topology,
            Topology::DelimiterComplementBoundedTerminalDelimiter
        );
        assert!(!identity.unicode);
        assert!(identity.greedy);
        assert!(identity.blocking_delimiter);
        assert!(identity.non_overlapping);
        assert!(matches!(
            BlockingDelimiterPlan::build([b'\'', b'"'], words(b"?!."), 30, BuildLimits::default()),
            Err(BuildError::NonCanonicalDelimiters)
        ));
        assert!(matches!(
            BlockingDelimiterPlan::build(DELIMITERS, words(b"?'"), 30, BuildLimits::default()),
            Err(BuildError::TerminalContainsDelimiter { .. })
        ));
    }

    #[test]
    fn every_positive_limit_is_preflighted_at_exact_and_one_below() {
        let build = plan(30).build_accounting();
        for limits in [
            BuildLimits {
                max_delimiter_members: build.delimiter_members - 1,
                ..BuildLimits::default()
            },
            BuildLimits {
                max_terminal_members: build.terminal_members - 1,
                ..BuildLimits::default()
            },
            BuildLimits {
                max_middle_bytes: build.maximum_middle_bytes - 1,
                ..BuildLimits::default()
            },
            BuildLimits {
                max_build_work: build.work_upper_bound - 1,
                ..BuildLimits::default()
            },
            BuildLimits {
                max_persistent_bytes: build.persistent_bytes - 1,
                ..BuildLimits::default()
            },
            BuildLimits {
                max_peak_bytes: build.peak_bytes - 1,
                ..BuildLimits::default()
            },
        ] {
            assert!(BlockingDelimiterPlan::build(DELIMITERS, words(b"?!."), 30, limits).is_err());
        }

        let plan = plan(30);
        let haystack = b"\"question?\" and 'answer!'";
        let upper = plan
            .span_sum(haystack, ReduceLimits::default())
            .unwrap()
            .accounting
            .upper_bounds;
        let cases = [
            ReduceLimits {
                max_input_bytes: upper.input_bytes - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_source_reads: upper.source_reads - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_work: upper.work - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_delimiter_scan_bytes: upper.delimiter_scan_bytes - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_delimiter_events: upper.delimiter_events - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_pair_events: upper.pair_events - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_terminal_reads: upper.terminal_reads - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_match_events: upper.match_events - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_count: upper.count - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_span_sum: upper.span_sum - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_persistent_bytes: upper.persistent_bytes - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_peak_bytes: upper.peak_bytes - 1,
                ..ReduceLimits::default()
            },
        ];
        for limits in cases {
            assert!(plan.span_sum(haystack, limits).is_err());
        }
    }

    #[test]
    fn build_attempt_reports_exact_success_and_partial_failure() {
        let attempt = BlockingDelimiterPlan::build_attempt(
            DELIMITERS,
            words(b"?!."),
            30,
            BuildLimits::default(),
        )
        .unwrap();
        let actual = attempt.actual();
        let (plan, returned_actual) = attempt.into_parts();
        let build = plan.build_accounting();
        assert_eq!(returned_actual, actual);
        assert_eq!(actual.work, u64::try_from(build.work_upper_bound).unwrap());
        assert_eq!(actual.allocations, 0);
        assert_eq!(actual.allocated_bytes, 0);
        assert_eq!(
            actual.copied_bytes,
            core::mem::size_of::<[u8; 2]>() + core::mem::size_of::<[u64; 4]>()
        );
        assert_eq!(actual.initialized_bytes, build.persistent_bytes);
        assert_eq!(actual.live_persistent_bytes, build.persistent_bytes);
        assert_eq!(actual.peak_bytes, build.peak_bytes);

        let error =
            BlockingDelimiterPlan::build_attempt(DELIMITERS, [0; 4], 30, BuildLimits::default())
                .unwrap_err();
        assert!(matches!(error.source(), BuildError::EmptyTerminalClass));
        assert_eq!(
            error.actual().work,
            u64::try_from(4 * TERMINAL_WORD_BUILD_WORK).unwrap()
        );
        assert_eq!(error.actual().allocations, 0);
        assert_eq!(error.actual().initialized_bytes, 0);
        assert_eq!(error.actual().live_persistent_bytes, 0);
        assert_eq!(error.actual().peak_bytes, 0);
    }
}
