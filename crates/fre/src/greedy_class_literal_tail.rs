//! Complete-span visitation for a greedy byte-class/literal/tail corridor.
//!
//! The admitted capture-transparent HIR is `PREFIX* LITERAL TAIL*`, where
//! both repetitions are greedy, unbounded byte classes and the literal is
//! nonempty. For one search cursor, the first literal occurrence determines
//! the earliest possible match start: that start extends backwards through
//! the adjacent `PREFIX` run, but never before the cursor. Greedy prefix
//! selection then chooses the last literal occurrence whose start is at or
//! before the end of that run. Finally, the tail extends through its maximal
//! class run. Restarting at the positive-width selected end yields exactly
//! Rust bytes' non-overlapping leftmost-first stream.
//!
//! Both literal searches and all class runs are monotone. The visitor retains
//! one exact literal allocation, uses no operation scratch, and preflights a
//! conservative linear source/work envelope before reading the haystack or
//! invoking the first callback.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "runtime arithmetic is dominated by the checked preflight envelope"
)]

use core::{fmt, mem::size_of};

use memchr::{
    memchr,
    memmem::{Finder, FinderRev},
};
use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind};

/// Stable identity of the construction-proved greedy corridor sidecar.
pub const PLAN_ID: &str = "greedy-class-literal-tail.complete-spans.v1";
/// Stable identity of allocation-free complete-span visitation.
pub const SPAN_VISIT_OPERATION_ID: &str = "greedy-class-literal-tail.span-visit.unicode-off.v1";

const FIXED_WORK: u64 = 32;
const FINDER_CALL_WORK: u64 = 4;
const CLASSIFICATION_WORK: u64 = 2;
const MATCH_WORK: u64 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ByteClass {
    words: [u64; 4],
    ranges: usize,
    excluded_singleton: Option<u8>,
}

impl ByteClass {
    fn singleton(byte: u8) -> Self {
        let mut words = [0_u64; 4];
        let word = usize::from(byte >> 6);
        let bit = u32::from(byte & 63);
        words[word] = 1_u64 << bit;
        Self {
            words,
            ranges: 1,
            excluded_singleton: None,
        }
    }

    fn from_hir(class: &ClassBytes) -> Self {
        let mut words = [0_u64; 4];
        for range in class.ranges() {
            for byte in range.start()..=range.end() {
                let word = usize::from(byte >> 6);
                let bit = u32::from(byte & 63);
                words[word] |= 1_u64 << bit;
            }
        }
        let excluded_singleton = one_byte_complement(class);
        Self {
            words,
            ranges: class.ranges().len(),
            excluded_singleton,
        }
    }

    #[inline]
    fn contains(self, byte: u8) -> bool {
        let word = usize::from(byte >> 6);
        let bit = u32::from(byte & 63);
        self.words[word] & (1_u64 << bit) != 0
    }

    fn forward_run(self, haystack: &[u8], start: usize) -> (usize, usize) {
        let remaining = &haystack[start..];
        if let Some(excluded) = self.excluded_singleton {
            return memchr(excluded, remaining)
                .map_or((haystack.len(), remaining.len()), |relative| {
                    (start + relative, relative + 1)
                });
        }
        let mut end = start;
        let mut probes = 0_usize;
        while let Some(&byte) = haystack.get(end) {
            probes += 1;
            if !self.contains(byte) {
                break;
            }
            end += 1;
        }
        (end, probes)
    }
}

fn one_byte_complement(class: &ClassBytes) -> Option<u8> {
    match class.ranges() {
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

/// Source-proved language geometry retained by the sidecar.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the booleans authenticate independent semantic proof obligations"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub literal_bytes: usize,
    pub prefix_class_words: [u64; 4],
    pub tail_class_words: [u64; 4],
    pub prefix_class_ranges: usize,
    pub tail_class_ranges: usize,
    pub greedy_prefix: bool,
    pub greedy_tail: bool,
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
    pub class_probes: usize,
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
    pub prefix_class_probes: usize,
    pub tail_class_probes: usize,
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
    pub max_class_probes: usize,
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
            max_class_probes: usize::MAX,
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
            max_source_reads: 512 * 1024 * 1024,
            max_work: 1_500_000_000,
            max_finder_calls: 128 * 1024 * 1024,
            max_class_probes: 128 * 1024 * 1024,
            max_match_events: 64 * 1024 * 1024,
            max_count: 64 * 1024 * 1024,
            max_span_sum: 64 * 1024 * 1024,
            max_scratch_bytes: 0,
            max_persistent_bytes: 1024 * 1024,
            max_peak_bytes: 1024 * 1024,
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
    ClassProbeLimit { needed: usize, limit: usize },
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
                write!(
                    formatter,
                    "greedy class/literal/tail {computation} overflowed"
                )
            }
            Self::InputBytesLimit { needed, limit } => write!(
                formatter,
                "greedy class/literal/tail needs {needed} input bytes, limit is {limit}",
            ),
            Self::SourceReadsLimit { needed, limit } => write!(
                formatter,
                "greedy class/literal/tail needs {needed} source reads, limit is {limit}",
            ),
            Self::WorkLimit { needed, limit } => write!(
                formatter,
                "greedy class/literal/tail needs {needed} work, limit is {limit}",
            ),
            Self::FinderCallLimit { needed, limit } => write!(
                formatter,
                "greedy class/literal/tail needs {needed} finder calls, limit is {limit}",
            ),
            Self::ClassProbeLimit { needed, limit } => write!(
                formatter,
                "greedy class/literal/tail needs {needed} class probes, limit is {limit}",
            ),
            Self::MatchEventLimit { needed, limit } => write!(
                formatter,
                "greedy class/literal/tail needs {needed} match events, limit is {limit}",
            ),
            Self::CountLimit { needed, limit } => write!(
                formatter,
                "greedy class/literal/tail needs count {needed}, limit is {limit}",
            ),
            Self::SpanSumLimit { needed, limit } => write!(
                formatter,
                "greedy class/literal/tail needs span sum {needed}, limit is {limit}",
            ),
            Self::ScratchLimit { needed, limit } => write!(
                formatter,
                "greedy class/literal/tail needs {needed} scratch bytes, limit is {limit}",
            ),
            Self::PersistentLimit { needed, limit } => write!(
                formatter,
                "greedy class/literal/tail needs {needed} persistent bytes, limit is {limit}",
            ),
            Self::PeakLimit { needed, limit } => write!(
                formatter,
                "greedy class/literal/tail needs {needed} peak bytes, limit is {limit}",
            ),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Result {
    pub matches: usize,
    pub span_sum: u64,
    pub accounting: Accounting,
}

/// Immutable owner built only from the certified HIR.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    prefix: ByteClass,
    literal: Vec<u8>,
    tail: ByteClass,
}

impl Plan {
    pub(crate) const fn identity(&self) -> Identity {
        Identity {
            plan_id: PLAN_ID,
            operation_id: SPAN_VISIT_OPERATION_ID,
            literal_bytes: self.literal.len(),
            prefix_class_words: self.prefix.words,
            tail_class_words: self.tail.words,
            prefix_class_ranges: self.prefix.ranges,
            tail_class_ranges: self.tail.ranges,
            greedy_prefix: true,
            greedy_tail: true,
            non_overlapping: true,
            unicode: false,
        }
    }

    pub(crate) fn storage_bytes(&self) -> usize {
        size_of::<Self>()
            .checked_add(self.literal.len())
            .expect("published plan storage was checked at construction")
    }

    fn upper_bounds(&self, input_bytes: usize) -> core::result::Result<UpperBounds, Error> {
        let match_events = input_bytes / self.literal.len();
        let finder_calls = match_events
            .checked_mul(2)
            .and_then(|calls| calls.checked_add(1))
            .ok_or(Error::ArithmeticOverflow {
                computation: "finder-call upper bound",
            })?;
        // Successful forward finder service is disjoint and at most N.
        // Reverse service may overlap the following segment by at most one
        // literal width per match, so 2N is conservative for it.
        let finder_service_bytes = input_bytes
            .checked_mul(3)
            .ok_or(Error::ArithmeticOverflow {
                computation: "finder-service upper bound",
            })?;
        // Backward/forward prefix probes and tail probes each have a 2N
        // envelope including terminating failures.
        let class_probes = input_bytes
            .checked_mul(4)
            .ok_or(Error::ArithmeticOverflow {
                computation: "class-probe upper bound",
            })?;
        let source_reads = u64::try_from(finder_service_bytes)
            .ok()
            .and_then(|finder| {
                u64::try_from(class_probes)
                    .ok()
                    .and_then(|classes| finder.checked_add(classes))
            })
            .ok_or(Error::ArithmeticOverflow {
                computation: "source-read upper bound",
            })?;
        let count = u64::try_from(match_events).map_err(|_| Error::ArithmeticOverflow {
            computation: "match-event count",
        })?;
        let span_sum = u64::try_from(input_bytes).map_err(|_| Error::ArithmeticOverflow {
            computation: "span-sum upper bound",
        })?;
        let work = FIXED_WORK
            .checked_add(u64::try_from(finder_service_bytes).unwrap_or(u64::MAX))
            .and_then(|work| {
                u64::try_from(finder_calls)
                    .ok()
                    .and_then(|calls| calls.checked_mul(FINDER_CALL_WORK))
                    .and_then(|calls| work.checked_add(calls))
            })
            .and_then(|work| {
                u64::try_from(class_probes)
                    .ok()
                    .and_then(|probes| probes.checked_mul(CLASSIFICATION_WORK))
                    .and_then(|probes| work.checked_add(probes))
            })
            .and_then(|work| {
                count
                    .checked_mul(MATCH_WORK)
                    .and_then(|matches| work.checked_add(matches))
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
            class_probes,
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
        refuse!(class_probes, max_class_probes, ClassProbeLimit);
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
        let upper = self.preflight(haystack.len(), limits)?;
        let finder = Finder::new(&self.literal);
        let reverse = FinderRev::new(&self.literal);
        let mut actual = Actual::default();
        let mut cursor = 0_usize;

        loop {
            actual.finder_calls += 1;
            let searched = &haystack[cursor..];
            let Some(relative) = finder.find(searched) else {
                actual.finder_service_bytes += searched.len();
                break;
            };
            let first_literal = cursor + relative;
            actual.finder_service_bytes += relative + self.literal.len();

            let mut start = first_literal;
            while start > cursor {
                actual.prefix_class_probes += 1;
                if !self.prefix.contains(haystack[start - 1]) {
                    break;
                }
                start -= 1;
            }

            let (prefix_end, forward_probes) = self.prefix.forward_run(haystack, first_literal);
            actual.prefix_class_probes += forward_probes;
            let reverse_end = prefix_end
                .saturating_add(self.literal.len())
                .min(haystack.len());
            actual.finder_calls += 1;
            let selected_literal = reverse
                .rfind(&haystack[first_literal..reverse_end])
                .map(|relative| first_literal + relative)
                .expect("the first literal remains in the reverse search window");
            actual.finder_service_bytes += reverse_end - selected_literal;

            let literal_end = selected_literal + self.literal.len();
            let (end, tail_probes) = self.tail.forward_run(haystack, literal_end);
            actual.tail_class_probes += tail_probes;
            let width = end - start;
            actual.matches += 1;
            actual.span_sum +=
                u64::try_from(width).expect("preflight proves every visited span width fits u64");
            visitor(Span { start, end });
            cursor = end;
        }

        let class_probes = actual.prefix_class_probes + actual.tail_class_probes;
        actual.source_reads = u64::try_from(actual.finder_service_bytes)
            .ok()
            .and_then(|finder| {
                u64::try_from(class_probes)
                    .ok()
                    .and_then(|classes| finder.checked_add(classes))
            })
            .expect("preflight proves source-read accounting fits u64");
        actual.work = FIXED_WORK
            + u64::try_from(actual.finder_service_bytes).expect("finder service fits u64")
            + u64::try_from(actual.finder_calls).expect("finder calls fit u64") * FINDER_CALL_WORK
            + u64::try_from(class_probes).expect("class probes fit u64") * CLASSIFICATION_WORK
            + u64::try_from(actual.matches).expect("matches fit u64") * MATCH_WORK;
        debug_assert!(actual.source_reads <= upper.source_reads);
        debug_assert!(actual.work <= upper.work);
        debug_assert!(actual.finder_calls <= upper.finder_calls);
        debug_assert!(actual.finder_service_bytes <= upper.finder_service_bytes);
        debug_assert!(class_probes <= upper.class_probes);
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

#[derive(Clone, Copy, Debug)]
pub(crate) struct Inspection<'a> {
    prefix: ByteClass,
    literal: &'a [u8],
    tail: ByteClass,
    pub(crate) planner_work: u64,
}

impl Inspection<'_> {
    pub(crate) fn storage_bytes(&self) -> Option<usize> {
        size_of::<Plan>().checked_add(self.literal.len())
    }

    pub(crate) fn build(self) -> core::result::Result<Plan, fre_exact_alloc::CopyError> {
        Ok(Plan {
            prefix: self.prefix,
            literal: fre_exact_alloc::copy_exact(self.literal)?,
            tail: self.tail,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum InspectionOutcome<'a> {
    Eligible(Inspection<'a>),
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
    const fn new(work: u64, limit: u64) -> Self {
        Self { work, limit }
    }

    fn charge(&mut self, units: usize) -> core::result::Result<(), InspectionError> {
        let units = u64::try_from(units).map_err(|_| InspectionError::ArithmeticOverflow)?;
        let needed = self
            .work
            .checked_add(units)
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

fn peel_captures<'h>(
    mut hir: &'h Hir,
    meter: &mut Meter,
) -> core::result::Result<&'h Hir, InspectionError> {
    loop {
        meter.charge(1)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = &capture.sub;
    }
}

fn greedy_unbounded_byte_class(
    hir: &Hir,
    meter: &mut Meter,
) -> core::result::Result<Option<ByteClass>, InspectionError> {
    let hir = peel_captures(hir, meter)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(None);
    };
    meter.charge(1)?;
    if repetition.min != 0 || repetition.max.is_some() || !repetition.greedy {
        return Ok(None);
    }
    let sub = peel_captures(&repetition.sub, meter)?;
    match sub.kind() {
        HirKind::Class(Class::Bytes(class)) => {
            meter.charge(class.ranges().len())?;
            for range in class.ranges() {
                let width = usize::from(range.end())
                    .checked_sub(usize::from(range.start()))
                    .and_then(|difference| difference.checked_add(1))
                    .ok_or(InspectionError::ArithmeticOverflow)?;
                meter.charge(width)?;
            }
            Ok(Some(ByteClass::from_hir(class)))
        }
        HirKind::Literal(literal) if literal.0.len() == 1 => {
            meter.charge(1)?;
            Ok(Some(ByteClass::singleton(literal.0[0])))
        }
        _ => Ok(None),
    }
}

pub(crate) fn inspect(
    hir: &Hir,
    initial_work: u64,
    limit: u64,
) -> core::result::Result<InspectionOutcome<'_>, InspectionError> {
    let mut meter = Meter::new(initial_work, limit);
    let root = peel_captures(hir, &mut meter)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    meter.charge(parts.len())?;
    let [prefix, literal, tail] = parts.as_slice() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    let Some(prefix) = greedy_unbounded_byte_class(prefix, &mut meter)? else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    let literal = peel_captures(literal, &mut meter)?;
    let HirKind::Literal(literal) = literal.kind() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    if literal.0.is_empty() {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    }
    meter.charge(literal.0.len())?;
    let Some(tail) = greedy_unbounded_byte_class(tail, &mut meter)? else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    Ok(InspectionOutcome::Eligible(Inspection {
        prefix,
        literal: &literal.0,
        tail,
        planner_work: meter.work,
    }))
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::{InspectionOutcome, Limits, inspect};

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
        inspection.build().unwrap()
    }

    fn oracle(pattern: &str, haystack: &[u8]) -> Vec<super::Span> {
        regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .map(|matched| super::Span {
                start: matched.start(),
                end: matched.end(),
            })
            .collect()
    }

    #[test]
    fn exact_greedy_corridor_shape_is_narrowly_admitted() {
        let admitted = plan(r"[ -~]*ABCDEFGHIJKLMNOPQRSTUVWXYZ.*");
        assert_eq!(admitted.identity().literal_bytes, 26);
        assert_eq!(admitted.identity().prefix_class_ranges, 1);
        assert_eq!(admitted.identity().tail_class_ranges, 2);
        for hostile in [
            r"[ -~]*?ABCDEFGHIJKLMNOPQRSTUVWXYZ.*",
            r"[ -~]+ABCDEFGHIJKLMNOPQRSTUVWXYZ.*",
            r"[ -~]*ABCDEFGHIJKLMNOPQRSTUVWXYZ.*?",
            r"[ -~]*ABCDEFGHIJKLMNOPQRSTUVWXYZ.+",
            r"[ -~]*ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            r"ABCDEFGHIJKLMNOPQRSTUVWXYZ.*",
            r"[ -~]*(ABCDEFGHIJKLMNOPQRSTUVWXYZ|ZYX).*",
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
    fn repeated_literals_lines_and_overlaps_match_the_oracle() {
        let cases: &[(&str, &[u8])] = &[
            (r"[a-z]*aba[^\n]*", b"xxabazaba!\nqaba--aba?\nnone"),
            (r"[ -~]*ABCDEFGHIJKLMNOPQRSTUVWXYZ.*", b"first ABCDEFGHIJKLMNOPQRSTUVWXYZ then ABCDEFGHIJKLMNOPQRSTUVWXYZ!\nnext ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"),
            (r"[ab]*aa[b]*", b"baaaacaaabaaaa"),
            (r"[^X]*XX[^Y]*", b"abXXXXcYdXXXefYXX"),
            (r"[x]*xy[z]*", b"xxxyzz!xyzzz"),
        ];
        for &(pattern, haystack) in cases {
            let plan = plan(pattern);
            let mut actual = Vec::new();
            let result = plan
                .visit_spans(haystack, Limits::unlimited(), |span| actual.push(span))
                .unwrap();
            let expected = oracle(pattern, haystack);
            assert_eq!(actual, expected, "{pattern:?} {haystack:?}");
            assert_eq!(result.matches, expected.len());
            assert_eq!(
                result.span_sum,
                expected
                    .iter()
                    .map(|span| u64::try_from(span.end - span.start).unwrap())
                    .sum(),
            );
        }
    }

    #[test]
    fn exhaustive_small_haystacks_match_regex_bytes() {
        let patterns = [r"[ab]*aa[^c]*", r"[^b]*aba[ac]*", r"[a]*a[^a]*"];
        for pattern in patterns {
            let plan = plan(pattern);
            for length in 0..=7_usize {
                let variants = 3_usize.pow(u32::try_from(length).unwrap());
                for mut encoded in 0..variants {
                    let mut haystack = vec![0_u8; length];
                    for byte in &mut haystack {
                        *byte = b'a' + u8::try_from(encoded % 3).unwrap();
                        encoded /= 3;
                    }
                    let mut actual = Vec::new();
                    plan.visit_spans(&haystack, Limits::unlimited(), |span| actual.push(span))
                        .unwrap();
                    assert_eq!(
                        actual,
                        oracle(pattern, &haystack),
                        "{pattern:?} {haystack:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_limit_refuses_before_callbacks() {
        let plan = plan(r"[ -~]*ABCDEFGHIJKLMNOPQRSTUVWXYZ.*");
        let haystack = b"line\nABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let baseline = plan
            .visit_spans(haystack, Limits::unlimited(), |_| {})
            .unwrap();
        let upper = baseline.accounting.upper_bounds;
        let mut limits = Vec::new();
        limits.push(Limits {
            max_input_bytes: upper.input_bytes - 1,
            ..Limits::unlimited()
        });
        limits.push(Limits {
            max_source_reads: upper.source_reads - 1,
            ..Limits::unlimited()
        });
        limits.push(Limits {
            max_work: upper.work - 1,
            ..Limits::unlimited()
        });
        limits.push(Limits {
            max_finder_calls: upper.finder_calls - 1,
            ..Limits::unlimited()
        });
        limits.push(Limits {
            max_class_probes: upper.class_probes - 1,
            ..Limits::unlimited()
        });
        limits.push(Limits {
            max_match_events: upper.match_events - 1,
            ..Limits::unlimited()
        });
        limits.push(Limits {
            max_count: upper.count - 1,
            ..Limits::unlimited()
        });
        limits.push(Limits {
            max_span_sum: upper.span_sum - 1,
            ..Limits::unlimited()
        });
        limits.push(Limits {
            max_persistent_bytes: upper.persistent_bytes - 1,
            ..Limits::unlimited()
        });
        limits.push(Limits {
            max_peak_bytes: upper.peak_bytes - 1,
            ..Limits::unlimited()
        });
        for limits in limits {
            let mut callbacks = 0;
            assert!(
                plan.visit_spans(haystack, limits, |_| callbacks += 1)
                    .is_err()
            );
            assert_eq!(callbacks, 0);
        }
    }
}
