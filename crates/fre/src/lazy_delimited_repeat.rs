//! Complete-span visitation for one exact lazy delimited-repeat language.
//!
//! The admitted HIR is `(CLASS*? DELIMITER){N} SUFFIX`, modulo the capture
//! wrapper produced by a source group, where `N > 0`, both literals are one
//! byte, and `CLASS` contains every byte except one barrier. The delimiter
//! must belong to the class. For any fixed start, lazy repetition selects the
//! first `DELIMITER SUFFIX` pair with at least `N` delimiters since the last
//! barrier. Unanchored leftmost-first search starts at that barrier boundary.
//! After a match, Rust byte iteration restarts at its end, so resetting the
//! same delimiter counter produces the complete non-overlapping stream.
//!
//! Execution enumerates pair candidates monotonically with one `memmem`
//! finder. Between candidates, disjoint gaps are classified with `memchr2`
//! for delimiter/barrier events. Finder service is at most `N + Q`, where
//! `N` is the source width and `Q <= N` is the number of overlapping pair
//! candidates; classified gap bytes are at most `N`. The complete envelope is
//! derived and checked before source access or the first callback.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all runtime arithmetic is dominated by a checked preflight envelope"
)]

use core::{fmt, mem::size_of};

use memchr::{memchr2, memmem::Finder};
use regex_syntax::hir::{Class, Hir, HirKind};

/// Stable identity of the construction-proved lazy delimited-repeat sidecar.
pub const PLAN_ID: &str = "lazy-delimited-repeat.complete-spans.v1";
/// Stable identity of allocation-free complete-span visitation.
pub const SPAN_VISIT_OPERATION_ID: &str = "lazy-delimited-repeat.span-visit.unicode-off.v1";

const FIXED_WORK: u64 = 32;
const FINDER_CALL_WORK: u64 = 4;
const EVENT_WORK: u64 = 2;
const PAIR_CANDIDATE_WORK: u64 = 4;
const MATCH_WORK: u64 = 8;

/// Source-proved language geometry retained by the sidecar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub repeat_count: usize,
    pub delimiter: u8,
    pub suffix: u8,
    pub barrier: u8,
    pub lazy: bool,
    pub exact_repeat: bool,
    pub non_overlapping: bool,
    pub unicode: bool,
}

/// Complete prospective resource envelope derived without a haystack read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpperBounds {
    pub input_bytes: usize,
    pub source_reads: u64,
    pub work: u64,
    pub finder_calls: usize,
    pub finder_service_bytes: usize,
    pub pair_candidates: usize,
    pub event_scan_bytes: usize,
    pub event_visits: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Exact no-clock counters from one completed traversal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Actual {
    pub source_reads: u64,
    pub work: u64,
    pub finder_calls: usize,
    pub finder_service_bytes: usize,
    pub pair_candidates: usize,
    pub event_scan_bytes: usize,
    pub event_visits: usize,
    pub matches: usize,
    pub span_sum: u64,
}

/// Closed receipt for one complete traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accounting {
    pub identity: Identity,
    pub upper_bounds: UpperBounds,
    pub actual: Actual,
}

/// Hard limits checked before source access or callbacks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_source_reads: u64,
    pub max_work: u64,
    pub max_finder_calls: usize,
    pub max_pair_candidates: usize,
    pub max_event_visits: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Limits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_input_bytes: usize::MAX,
            max_source_reads: u64::MAX,
            max_work: u64::MAX,
            max_finder_calls: usize::MAX,
            max_pair_candidates: usize::MAX,
            max_event_visits: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024 * 1024,
            max_source_reads: 256 * 1024 * 1024,
            max_work: 1_500_000_000,
            max_finder_calls: 64 * 1024 * 1024,
            max_pair_candidates: 64 * 1024 * 1024,
            max_event_visits: 64 * 1024 * 1024,
            max_match_events: 64 * 1024 * 1024,
            max_count: 64 * 1024 * 1024,
            max_span_sum: 64 * 1024 * 1024,
            max_scratch_bytes: 0,
            max_persistent_bytes: 1024,
            max_peak_bytes: 1024,
        }
    }
}

/// Checked refusal from complete-span visitation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    ArithmeticOverflow { computation: &'static str },
    InputBytesLimit { needed: usize, limit: usize },
    SourceReadsLimit { needed: u64, limit: u64 },
    WorkLimit { needed: u64, limit: u64 },
    FinderCallLimit { needed: usize, limit: usize },
    PairCandidateLimit { needed: usize, limit: usize },
    EventVisitLimit { needed: usize, limit: usize },
    MatchEventLimit { needed: usize, limit: usize },
    CountLimit { needed: u64, limit: u64 },
    SpanSumLimit { needed: u64, limit: u64 },
    ScratchLimit { needed: usize, limit: usize },
    PersistentLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArithmeticOverflow { computation } => {
                write!(formatter, "lazy delimited-repeat {computation} overflowed")
            }
            Self::InputBytesLimit { needed, limit } => write!(
                formatter,
                "lazy delimited-repeat needs {needed} input bytes, limit is {limit}",
            ),
            Self::SourceReadsLimit { needed, limit } => write!(
                formatter,
                "lazy delimited-repeat needs {needed} source reads, limit is {limit}",
            ),
            Self::WorkLimit { needed, limit } => write!(
                formatter,
                "lazy delimited-repeat needs {needed} work, limit is {limit}",
            ),
            Self::FinderCallLimit { needed, limit } => write!(
                formatter,
                "lazy delimited-repeat needs {needed} finder calls, limit is {limit}",
            ),
            Self::PairCandidateLimit { needed, limit } => write!(
                formatter,
                "lazy delimited-repeat needs {needed} pair candidates, limit is {limit}",
            ),
            Self::EventVisitLimit { needed, limit } => write!(
                formatter,
                "lazy delimited-repeat needs {needed} delimiter/barrier events, limit is {limit}",
            ),
            Self::MatchEventLimit { needed, limit } => write!(
                formatter,
                "lazy delimited-repeat needs {needed} match events, limit is {limit}",
            ),
            Self::CountLimit { needed, limit } => write!(
                formatter,
                "lazy delimited-repeat needs count {needed}, limit is {limit}",
            ),
            Self::SpanSumLimit { needed, limit } => write!(
                formatter,
                "lazy delimited-repeat needs span sum {needed}, limit is {limit}",
            ),
            Self::ScratchLimit { needed, limit } => write!(
                formatter,
                "lazy delimited-repeat needs {needed} scratch bytes, limit is {limit}",
            ),
            Self::PersistentLimit { needed, limit } => write!(
                formatter,
                "lazy delimited-repeat needs {needed} persistent bytes, limit is {limit}",
            ),
            Self::PeakLimit { needed, limit } => write!(
                formatter,
                "lazy delimited-repeat needs {needed} peak bytes, limit is {limit}",
            ),
        }
    }
}

impl std::error::Error for Error {}

/// One visited whole-match span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Span {
    pub start: usize,
    pub end: usize,
}

/// Result of a complete visit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Result {
    pub matches: usize,
    pub span_sum: u64,
    pub accounting: Accounting,
}

/// Inline immutable owner built only from the certified HIR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    repeat_count: usize,
    delimiter: u8,
    suffix: u8,
    barrier: u8,
}

impl Plan {
    pub(crate) const fn identity(&self) -> Identity {
        Identity {
            plan_id: PLAN_ID,
            operation_id: SPAN_VISIT_OPERATION_ID,
            repeat_count: self.repeat_count,
            delimiter: self.delimiter,
            suffix: self.suffix,
            barrier: self.barrier,
            lazy: true,
            exact_repeat: true,
            non_overlapping: true,
            unicode: false,
        }
    }

    pub(crate) const fn storage_bytes(&self) -> usize {
        size_of::<Self>()
    }

    fn upper_bounds(&self, input_bytes: usize) -> core::result::Result<UpperBounds, Error> {
        let pair_candidates = input_bytes.saturating_sub(1);
        let finder_calls = pair_candidates
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow {
                computation: "finder-call upper bound",
            })?;
        let finder_service_bytes =
            input_bytes
                .checked_add(pair_candidates)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "finder-service upper bound",
                })?;
        let event_scan_bytes = input_bytes;
        let event_visits = input_bytes;
        let minimum_match_bytes =
            self.repeat_count
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "minimum match width",
                })?;
        let match_events = input_bytes / minimum_match_bytes;
        let count = u64::try_from(match_events).map_err(|_| Error::ArithmeticOverflow {
            computation: "match-event count",
        })?;
        let span_sum = u64::try_from(input_bytes).map_err(|_| Error::ArithmeticOverflow {
            computation: "span-sum upper bound",
        })?;
        let source_reads = u64::try_from(finder_service_bytes)
            .ok()
            .and_then(|reads| {
                u64::try_from(event_scan_bytes)
                    .ok()
                    .and_then(|events| reads.checked_add(events))
            })
            .ok_or(Error::ArithmeticOverflow {
                computation: "source-read upper bound",
            })?;
        let work = FIXED_WORK
            .checked_add(u64::try_from(finder_service_bytes).unwrap_or(u64::MAX))
            .and_then(|value| {
                u64::try_from(finder_calls)
                    .ok()
                    .and_then(|calls| calls.checked_mul(FINDER_CALL_WORK))
                    .and_then(|calls| value.checked_add(calls))
            })
            .and_then(|value| {
                u64::try_from(event_scan_bytes)
                    .ok()
                    .and_then(|bytes| value.checked_add(bytes))
            })
            .and_then(|value| {
                u64::try_from(event_visits)
                    .ok()
                    .and_then(|events| events.checked_mul(EVENT_WORK))
                    .and_then(|events| value.checked_add(events))
            })
            .and_then(|value| {
                u64::try_from(pair_candidates)
                    .ok()
                    .and_then(|events| events.checked_mul(PAIR_CANDIDATE_WORK))
                    .and_then(|events| value.checked_add(events))
            })
            .and_then(|value| {
                count
                    .checked_mul(MATCH_WORK)
                    .and_then(|events| value.checked_add(events))
            })
            .ok_or(Error::ArithmeticOverflow {
                computation: "work upper bound",
            })?;
        let persistent_bytes = self.storage_bytes();
        Ok(UpperBounds {
            input_bytes,
            source_reads,
            work,
            finder_calls,
            finder_service_bytes,
            pair_candidates,
            event_scan_bytes,
            event_visits,
            match_events,
            count,
            span_sum,
            scratch_bytes: 0,
            persistent_bytes,
            peak_bytes: persistent_bytes,
        })
    }

    fn preflight(
        &self,
        input_bytes: usize,
        limits: Limits,
    ) -> core::result::Result<UpperBounds, Error> {
        let upper = self.upper_bounds(input_bytes)?;
        macro_rules! refuse {
            ($field:ident, $limit:ident, $variant:ident) => {
                if upper.$field > limits.$limit {
                    return Err(Error::$variant {
                        needed: upper.$field,
                        limit: limits.$limit,
                    });
                }
            };
        }
        refuse!(input_bytes, max_input_bytes, InputBytesLimit);
        refuse!(source_reads, max_source_reads, SourceReadsLimit);
        refuse!(work, max_work, WorkLimit);
        refuse!(finder_calls, max_finder_calls, FinderCallLimit);
        refuse!(pair_candidates, max_pair_candidates, PairCandidateLimit);
        refuse!(event_visits, max_event_visits, EventVisitLimit);
        refuse!(match_events, max_match_events, MatchEventLimit);
        refuse!(count, max_count, CountLimit);
        refuse!(span_sum, max_span_sum, SpanSumLimit);
        refuse!(scratch_bytes, max_scratch_bytes, ScratchLimit);
        refuse!(persistent_bytes, max_persistent_bytes, PersistentLimit);
        refuse!(peak_bytes, max_peak_bytes, PeakLimit);
        Ok(upper)
    }

    pub(crate) fn visit_spans<F>(
        &self,
        haystack: &[u8],
        limits: Limits,
        mut visitor: F,
    ) -> core::result::Result<Result, Error>
    where
        F: FnMut(Span),
    {
        // No source slice or callback is touched before the entire envelope
        // closes. After this point every counter/index is dominated by it.
        let upper = self.preflight(haystack.len(), limits)?;
        let pair = [self.delimiter, self.suffix];
        let finder = Finder::new(&pair);
        let mut actual = Actual::default();
        let mut pair_cursor = 0_usize;
        let mut event_cursor = 0_usize;
        let mut match_start = 0_usize;
        let mut delimiter_count = 0_usize;

        while pair_cursor <= haystack.len() {
            actual.finder_calls += 1;
            let searched = &haystack[pair_cursor..];
            let Some(relative) = finder.find(searched) else {
                actual.finder_service_bytes += searched.len();
                break;
            };
            let pair_start = pair_cursor + relative;
            actual.finder_service_bytes += relative + pair.len();
            actual.pair_candidates += 1;

            let gap = &haystack[event_cursor..pair_start];
            actual.event_scan_bytes += gap.len();
            let mut gap_cursor = 0_usize;
            while let Some(relative_event) =
                memchr2(self.delimiter, self.barrier, &gap[gap_cursor..])
            {
                let event = gap_cursor + relative_event;
                actual.event_visits += 1;
                if gap[event] == self.barrier {
                    delimiter_count = 0;
                    match_start = event_cursor + event + 1;
                } else {
                    delimiter_count += 1;
                }
                gap_cursor = event + 1;
            }

            let candidate_delimiters = delimiter_count + 1;
            if candidate_delimiters >= self.repeat_count {
                let end = pair_start + pair.len();
                let width = end - match_start;
                actual.matches += 1;
                actual.span_sum += u64::try_from(width)
                    .expect("preflight proves every visited span width fits u64");
                visitor(Span {
                    start: match_start,
                    end,
                });
                delimiter_count = 0;
                match_start = end;
                event_cursor = end;
                pair_cursor = end;
            } else {
                delimiter_count = candidate_delimiters;
                event_cursor = pair_start + 1;
                pair_cursor = pair_start + 1;
            }
        }

        actual.source_reads = u64::try_from(actual.finder_service_bytes)
            .ok()
            .and_then(|reads| {
                u64::try_from(actual.event_scan_bytes)
                    .ok()
                    .and_then(|events| reads.checked_add(events))
            })
            .expect("preflight proves source-read accounting fits u64");
        actual.work = FIXED_WORK
            + u64::try_from(actual.finder_service_bytes).expect("finder service fits u64")
            + u64::try_from(actual.finder_calls).expect("finder calls fit u64") * FINDER_CALL_WORK
            + u64::try_from(actual.event_scan_bytes).expect("event scan fits u64")
            + u64::try_from(actual.event_visits).expect("event visits fit u64") * EVENT_WORK
            + u64::try_from(actual.pair_candidates).expect("pair candidates fit u64")
                * PAIR_CANDIDATE_WORK
            + u64::try_from(actual.matches).expect("matches fit u64") * MATCH_WORK;
        debug_assert!(actual.source_reads <= upper.source_reads);
        debug_assert!(actual.work <= upper.work);
        debug_assert!(actual.finder_calls <= upper.finder_calls);
        debug_assert!(actual.finder_service_bytes <= upper.finder_service_bytes);
        debug_assert!(actual.pair_candidates <= upper.pair_candidates);
        debug_assert!(actual.event_scan_bytes <= upper.event_scan_bytes);
        debug_assert!(actual.event_visits <= upper.event_visits);
        debug_assert!(actual.matches <= upper.match_events);
        debug_assert!(actual.span_sum <= upper.span_sum);
        Ok(Result {
            matches: actual.matches,
            span_sum: actual.span_sum,
            accounting: Accounting {
                identity: self.identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Inspection {
    pub(crate) plan: Plan,
    pub(crate) planner_work: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionOutcome {
    Eligible(Inspection),
    Ineligible { planner_work: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit {
        actual: u64,
        needed: u64,
        limit: u64,
    },
    ArithmeticOverflow,
}

struct Meter {
    work: u64,
    limit: u64,
}

impl Meter {
    fn new(work: u64, limit: u64) -> Self {
        Self { work, limit }
    }

    fn charge(&mut self) -> core::result::Result<(), InspectionError> {
        let needed = self
            .work
            .checked_add(1)
            .ok_or(InspectionError::ArithmeticOverflow)?;
        if needed > self.limit {
            return Err(InspectionError::WorkLimit {
                actual: self.work,
                needed,
                limit: self.limit,
            });
        }
        self.work = needed;
        Ok(())
    }
}

fn unwrap_capture<'h>(
    hir: &'h Hir,
    meter: &mut Meter,
) -> core::result::Result<&'h Hir, InspectionError> {
    meter.charge()?;
    Ok(match hir.kind() {
        HirKind::Capture(capture) => &capture.sub,
        _ => hir,
    })
}

fn one_byte_literal(
    hir: &Hir,
    meter: &mut Meter,
) -> core::result::Result<Option<u8>, InspectionError> {
    meter.charge()?;
    let HirKind::Literal(literal) = hir.kind() else {
        return Ok(None);
    };
    Ok((literal.0.len() == 1).then(|| literal.0[0]))
}

fn one_byte_complement(class: &Class) -> Option<u8> {
    let Class::Bytes(class) = class else {
        return None;
    };
    let ranges = class.ranges();
    match ranges {
        [only] if only.start() == 1 && only.end() == u8::MAX => Some(0),
        [only] if only.start() == 0 && only.end() == u8::MAX - 1 => Some(u8::MAX),
        [left, right]
            if left.start() == 0
                && right.end() == u8::MAX
                && left.end().checked_add(2) == Some(right.start()) =>
        {
            left.end().checked_add(1)
        }
        _ => None,
    }
}

pub(crate) fn inspect(
    hir: &Hir,
    initial_work: u64,
    limit: u64,
) -> core::result::Result<InspectionOutcome, InspectionError> {
    let mut meter = Meter::new(initial_work, limit);
    meter.charge()?;
    let HirKind::Concat(root) = hir.kind() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    if root.len() != 2 {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    }
    let Some(suffix) = one_byte_literal(&root[1], &mut meter)? else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    meter.charge()?;
    let HirKind::Repetition(outer) = root[0].kind() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    if outer.min == 0 || outer.max != Some(outer.min) || !outer.greedy {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    }
    let repeat_count =
        usize::try_from(outer.min).map_err(|_| InspectionError::ArithmeticOverflow)?;
    let unit = unwrap_capture(&outer.sub, &mut meter)?;
    meter.charge()?;
    let HirKind::Concat(unit) = unit.kind() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    if unit.len() != 2 {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    }
    let Some(delimiter) = one_byte_literal(&unit[1], &mut meter)? else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    meter.charge()?;
    let HirKind::Repetition(inner) = unit[0].kind() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    if inner.min != 0 || inner.max.is_some() || inner.greedy {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    }
    meter.charge()?;
    let HirKind::Class(class) = inner.sub.kind() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    let Some(barrier) = one_byte_complement(class) else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    if delimiter == barrier {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    }
    Ok(InspectionOutcome::Eligible(Inspection {
        plan: Plan {
            repeat_count,
            delimiter,
            suffix,
            barrier,
        },
        planner_work: meter.work,
    }))
}

#[cfg(test)]
mod tests {
    use super::{InspectionOutcome, Limits, inspect};
    use regex_syntax::ParserBuilder;

    fn plan(pattern: &str) -> super::Plan {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap();
        let InspectionOutcome::Eligible(inspection) = inspect(&hir, 0, u64::MAX).unwrap() else {
            panic!("pattern was ineligible: {pattern:?}");
        };
        inspection.plan
    }

    #[test]
    fn exact_lazy_delimited_shape_is_narrowly_admitted() {
        let admitted = plan(r"(.*?,){13}z");
        assert_eq!(admitted.identity().repeat_count, 13);
        for hostile in [
            r"(.*?,){0}z",
            r"(.*?,){1,13}z",
            r"(.*,){13}z",
            r"(.+?,){13}z",
            r"(.*?;){13}zz",
            r"(.*?\n){13}z",
            r"(.*?,){13}",
        ] {
            let hir = ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .build()
                .parse(hostile)
                .unwrap();
            assert!(
                matches!(
                    inspect(&hir, 0, u64::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. }
                ),
                "hostile shape admitted: {hostile:?}",
            );
        }
    }

    #[test]
    fn limits_refuse_before_callbacks() {
        let plan = plan(r"(.*?,){2}z");
        let mut callbacks = 0;
        let error = plan
            .visit_spans(
                b"a,b,c,z",
                Limits {
                    max_input_bytes: 6,
                    ..Limits::unlimited()
                },
                |_| callbacks += 1,
            )
            .unwrap_err();
        assert!(matches!(error, super::Error::InputBytesLimit { .. }));
        assert_eq!(callbacks, 0);
    }
}
